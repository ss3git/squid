/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 11    Hypertext Transfer Protocol (HTTP) */

/*
 * Anonymizing patch by lutz@as-node.jena.thur.de
 * have a look into http-anon.c to get more information.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncJobCalls.h"
#include "base/DelayedAsyncCalls.h"
#include "base/Raw.h"
#include "base/TextException.h"
#include "base64.h"
#include "CachePeer.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "error/Detail.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "http.h"
#include "http/one/ResponseParser.h"
#include "http/one/TeChunkedParser.h"
#include "http/StatusCode.h"
#include "http/Stream.h"
#include "HttpControlMsg.h"
#include "HttpHdrCc.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpHdrScTarget.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "HttpUpgradeProtocolAccess.h"
#include "log/access_log.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "neighbors.h"
#include "pconn.h"
#include "peer_proxy_negotiate_auth.h"
#include "refresh.h"
#include "RefreshPattern.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "StatCounters.h"
#include "Store.h"
#include "StrList.h"
#include "tools.h"
#include "util.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

CBDATA_CLASS_INIT(HttpStateData);

static const char *const crlf = "\r\n";

static void httpMaybeRemovePublic(StoreEntry *, Http::StatusCode);
static void copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, const String strConnection, const HttpRequest * request,
        HttpHeader * hdr_out, const int we_do_ranges, const Http::StateFlags &);

HttpStateData::HttpStateData(FwdState *theFwdState) :
    AsyncJob("HttpStateData"),
    Client(theFwdState)
{
    debugs(11,5, "HttpStateData " << this << " created");
    serverConnection = fwd->serverConnection();

    if (fwd->serverConnection() != nullptr)
        _peer = cbdataReference(fwd->serverConnection()->getPeer());         /* might be NULL */

    flags.peering =  _peer;
    flags.tunneling = (_peer && request->flags.sslBumped);
    flags.toOrigin = (!_peer || _peer->options.originserver || request->flags.sslBumped);

    if (_peer) {
        /*
         * This NEIGHBOR_PROXY_ONLY check probably shouldn't be here.
         * We might end up getting the object from somewhere else if,
         * for example, the request to this neighbor fails.
         */
        if (!flags.tunneling && _peer->options.proxy_only)
            entry->releaseRequest(true);

#if USE_DELAY_POOLS
        entry->setNoDelay(_peer->options.no_delay);
#endif
    }

    /*
     * register the handler to free HTTP state data when the FD closes
     */
    typedef CommCbMemFunT<HttpStateData, CommCloseCbParams> Dialer;
    closeHandler = JobCallback(9, 5, Dialer, this, HttpStateData::httpStateConnClosed);
    comm_add_close_handler(serverConnection->fd, closeHandler);
}

HttpStateData::~HttpStateData()
{
    /*
     * don't forget that ~Client() gets called automatically
     */

    if (httpChunkDecoder)
        delete httpChunkDecoder;

    cbdataReferenceDone(_peer);

    delete upgradeHeaderOut;

    debugs(11,5, "HttpStateData " << this << " destroyed; " << serverConnection);
}

const Comm::ConnectionPointer &
HttpStateData::dataConnection() const
{
    return serverConnection;
}

void
HttpStateData::httpStateConnClosed(const CommCloseCbParams &params)
{
    debugs(11, 5, "httpStateFree: FD " << params.fd << ", httpState=" << params.data);
    doneWithFwd = "httpStateConnClosed()"; // assume FwdState is monitoring too
    mustStop("HttpStateData::httpStateConnClosed");
}

void
HttpStateData::httpTimeout(const CommTimeoutCbParams &)
{
    debugs(11, 4, serverConnection << ": '" << entry->url() << "'");

    if (entry->store_status == STORE_PENDING) {
        fwd->fail(new ErrorState(ERR_READ_TIMEOUT, Http::scGatewayTimeout, fwd->request, fwd->al));
    }

    closeServer();
    mustStop("HttpStateData::httpTimeout");
}

static StoreEntry *
findPreviouslyCachedEntry(StoreEntry *newEntry) {
    assert(newEntry->mem_obj);
    return newEntry->mem_obj->request ?
           storeGetPublicByRequest(newEntry->mem_obj->request.getRaw()) :
           storeGetPublic(newEntry->mem_obj->storeId(), newEntry->mem_obj->method);
}

/// Remove an existing public store entry if the incoming response (to be
/// stored in a currently private entry) is going to invalidate it.
static void
httpMaybeRemovePublic(StoreEntry * e, Http::StatusCode status)
{
    int remove = 0;
    int forbidden = 0;

    // If the incoming response already goes into a public entry, then there is
    // nothing to remove. This protects ready-for-collapsing entries as well.
    if (!EBIT_TEST(e->flags, KEY_PRIVATE))
        return;

    // If the new/incoming response cannot be stored, then it does not
    // compete with the old stored response for the public key, and the
    // old stored response should be left as is.
    if (e->mem_obj->request && !e->mem_obj->request->flags.cachable)
        return;

    switch (status) {

    case Http::scOkay:

    case Http::scNonAuthoritativeInformation:

    case Http::scMultipleChoices:

    case Http::scMovedPermanently:

    case Http::scFound:

    case Http::scSeeOther:

    case Http::scGone:

    case Http::scNotFound:
        remove = 1;

        break;

    case Http::scForbidden:

    case Http::scMethodNotAllowed:
        forbidden = 1;

        break;

#if WORK_IN_PROGRESS

    case Http::scUnauthorized:
        forbidden = 1;

        break;

#endif

    default:
        break;
    }

    if (!remove && !forbidden)
        return;

    StoreEntry *pe = findPreviouslyCachedEntry(e);

    if (pe != nullptr) {
        assert(e != pe);
#if USE_HTCP
        neighborsHtcpClear(e, e->mem_obj->request.getRaw(), e->mem_obj->method, HTCP_CLR_INVALIDATION);
#endif
        pe->release(true);
    }

    /** \par
     * Also remove any cached HEAD response in case the object has
     * changed.
     */
    if (e->mem_obj->request)
        pe = storeGetPublicByRequestMethod(e->mem_obj->request.getRaw(), Http::METHOD_HEAD);
    else
        pe = storeGetPublic(e->mem_obj->storeId(), Http::METHOD_HEAD);

    if (pe != nullptr) {
        assert(e != pe);
#if USE_HTCP
        neighborsHtcpClear(e, e->mem_obj->request.getRaw(), HttpRequestMethod(Http::METHOD_HEAD), HTCP_CLR_INVALIDATION);
#endif
        pe->release(true);
    }
}

void
HttpStateData::processSurrogateControl(HttpReply *reply)
{
    if (request->flags.accelerated && reply->surrogate_control) {
        HttpHdrScTarget *sctusable = reply->surrogate_control->getMergedTarget(Config.Accel.surrogate_id);

        if (sctusable) {
            if (sctusable->hasNoStore() ||
                    (Config.onoff.surrogate_is_remote
                     && sctusable->noStoreRemote())) {
                surrogateNoStore = true;
                // Be conservative for now and make it non-shareable because
                // there is no enough information here to make the decision.
                entry->makePrivate(false);
            }

            /* The HttpHeader logic cannot tell if the header it's parsing is a reply to an
             * accelerated request or not...
             * Still, this is an abstraction breach. - RC
             */
            if (sctusable->hasMaxAge()) {
                if (sctusable->maxAge() < sctusable->maxStale())
                    reply->expires = reply->date + sctusable->maxAge();
                else
                    reply->expires = reply->date + sctusable->maxStale();

                /* And update the timestamps */
                entry->timestampsSet();
            }

            /* We ignore cache-control directives as per the Surrogate specification */
            ignoreCacheControl = true;

            delete sctusable;
        }
    }
}

HttpStateData::ReuseDecision::Answers
HttpStateData::reusableReply(HttpStateData::ReuseDecision &decision)
{
    HttpReply const *rep = finalReply();
    HttpHeader const *hdr = &rep->header;
    const char *v;
#if USE_HTTP_VIOLATIONS

    const RefreshPattern *R = nullptr;

    /* This strange looking define first looks up the refresh pattern
     * and then checks if the specified flag is set. The main purpose
     * of this is to simplify the refresh pattern lookup and USE_HTTP_VIOLATIONS
     * condition
     */
#define REFRESH_OVERRIDE(flag) \
    ((R = (R ? R : refreshLimits(entry->mem_obj->storeId()))) , \
    (R && R->flags.flag))
#else
#define REFRESH_OVERRIDE(flag) 0
#endif

    if (EBIT_TEST(entry->flags, RELEASE_REQUEST))
        return decision.make(ReuseDecision::doNotCacheButShare, "the entry has been released");

    // RFC 9111 section 4:
    // "When more than one suitable response is stored,
    //  a cache MUST use the most recent one
    //  (as determined by the Date header field)."
    // TODO: whether such responses could be shareable?
    if (sawDateGoBack)
        return decision.make(ReuseDecision::reuseNot, "the response has an older date header");

    // Check for Surrogate/1.0 protocol conditions
    // NP: reverse-proxy traffic our parent server has instructed us never to cache
    if (surrogateNoStore)
        return decision.make(ReuseDecision::reuseNot, "Surrogate-Control:no-store");

    // RFC 2616: HTTP/1.1 Cache-Control conditions
    if (!ignoreCacheControl) {
        // XXX: check to see if the request headers alone were enough to prevent caching earlier
        // (ie no-store request header) no need to check those all again here if so.
        // for now we are not reliably doing that so we waste CPU re-checking request CC

        // RFC 2616 section 14.9.2 - MUST NOT cache any response with request CC:no-store
        if (request && request->cache_control && request->cache_control->hasNoStore() &&
                !REFRESH_OVERRIDE(ignore_no_store))
            return decision.make(ReuseDecision::reuseNot,
                                 "client request Cache-Control:no-store");

        // NP: request CC:no-cache only means cache READ is forbidden. STORE is permitted.
        if (rep->cache_control && rep->cache_control->hasNoCacheWithParameters()) {
            /* TODO: we are allowed to cache when no-cache= has parameters.
             * Provided we strip away any of the listed headers unless they are revalidated
             * successfully (ie, must revalidate AND these headers are prohibited on stale replies).
             * That is a bit tricky for squid right now so we avoid caching entirely.
             */
            return decision.make(ReuseDecision::reuseNot,
                                 "server reply Cache-Control:no-cache has parameters");
        }

        // NP: request CC:private is undefined. We ignore.
        // NP: other request CC flags are limiters on HIT/MISS. We don't care about here.

        // RFC 2616 section 14.9.2 - MUST NOT cache any response with CC:no-store
        if (rep->cache_control && rep->cache_control->hasNoStore() &&
                !REFRESH_OVERRIDE(ignore_no_store))
            return decision.make(ReuseDecision::reuseNot,
                                 "server reply Cache-Control:no-store");

        // RFC 2616 section 14.9.1 - MUST NOT cache any response with CC:private in a shared cache like Squid.
        // CC:private overrides CC:public when both are present in a response.
        // TODO: add a shared/private cache configuration possibility.
        if (rep->cache_control &&
                rep->cache_control->hasPrivate() &&
                !REFRESH_OVERRIDE(ignore_private)) {
            /* TODO: we are allowed to cache when private= has parameters.
             * Provided we strip away any of the listed headers unless they are revalidated
             * successfully (ie, must revalidate AND these headers are prohibited on stale replies).
             * That is a bit tricky for squid right now so we avoid caching entirely.
             */
            return decision.make(ReuseDecision::reuseNot,
                                 "server reply Cache-Control:private");
        }
    }

    // RFC 2068, sec 14.9.4 - MUST NOT cache any response with Authentication UNLESS certain CC controls are present
    // allow HTTP violations to IGNORE those controls (ie re-block caching Auth)
    if (request && (request->flags.auth || request->flags.authSent)) {
        if (!rep->cache_control)
            return decision.make(ReuseDecision::reuseNot,
                                 "authenticated and server reply missing Cache-Control");

        if (ignoreCacheControl)
            return decision.make(ReuseDecision::reuseNot,
                                 "authenticated and ignoring Cache-Control");

        bool mayStore = false;
        // HTTPbis pt6 section 3.2: a response CC:public is present
        if (rep->cache_control->hasPublic()) {
            debugs(22, 3, "Authenticated but server reply Cache-Control:public");
            mayStore = true;

            // HTTPbis pt6 section 3.2: a response CC:must-revalidate is present
        } else if (rep->cache_control->hasMustRevalidate()) {
            debugs(22, 3, "Authenticated but server reply Cache-Control:must-revalidate");
            mayStore = true;

#if USE_HTTP_VIOLATIONS
            // NP: given the must-revalidate exception we should also be able to exempt no-cache.
            // HTTPbis WG verdict on this is that it is omitted from the spec due to being 'unexpected' by
            // some. The caching+revalidate is not exactly unsafe though with Squids interpretation of no-cache
            // (without parameters) as equivalent to must-revalidate in the reply.
        } else if (rep->cache_control->hasNoCacheWithoutParameters()) {
            debugs(22, 3, "Authenticated but server reply Cache-Control:no-cache (equivalent to must-revalidate)");
            mayStore = true;
#endif

            // HTTPbis pt6 section 3.2: a response CC:s-maxage is present
        } else if (rep->cache_control->hasSMaxAge()) {
            debugs(22, 3, "Authenticated but server reply Cache-Control:s-maxage");
            mayStore = true;
        }

        if (!mayStore)
            return decision.make(ReuseDecision::reuseNot, "authenticated transaction");

        // NP: response CC:no-cache is equivalent to CC:must-revalidate,max-age=0. We MAY cache, and do so.
        // NP: other request CC flags are limiters on HIT/MISS/REFRESH. We don't care about here.
    }

    /* HACK: The "multipart/x-mixed-replace" content type is used for
     * continuous push replies.  These are generally dynamic and
     * probably should not be cachable
     */
    if ((v = hdr->getStr(Http::HdrType::CONTENT_TYPE)))
        if (!strncasecmp(v, "multipart/x-mixed-replace", 25))
            return decision.make(ReuseDecision::reuseNot, "Content-Type:multipart/x-mixed-replace");

    // TODO: if possible, provide more specific message for each status code
    static const char *shareableError = "shareable error status code";
    static const char *nonShareableError = "non-shareable error status code";
    ReuseDecision::Answers statusAnswer = ReuseDecision::reuseNot;
    const char *statusReason = nonShareableError;

    switch (rep->sline.status()) {

    /* There are several situations when a non-cacheable response may be
     * still shareable (e.g., among collapsed clients). We assume that these
     * are 3xx and 5xx responses, indicating server problems and some of
     * 4xx responses, common for all clients with a given cache key (e.g.,
     * 404 Not Found or 414 URI Too Long). On the other hand, we should not
     * share non-cacheable client-specific errors, such as 400 Bad Request
     * or 406 Not Acceptable.
     */

    /* Responses that are cacheable */

    case Http::scOkay:

    case Http::scNonAuthoritativeInformation:

    case Http::scMultipleChoices:

    case Http::scMovedPermanently:
    case Http::scPermanentRedirect:

    case Http::scGone:
        /*
         * Don't cache objects that need to be refreshed on next request,
         * unless we know how to refresh it.
         */

        if (refreshIsCachable(entry) || REFRESH_OVERRIDE(store_stale))
            decision.make(ReuseDecision::cachePositively, "refresh check returned cacheable");
        else
            decision.make(ReuseDecision::doNotCacheButShare, "refresh check returned non-cacheable");
        break;

    /* Responses that only are cacheable if the server says so */

    case Http::scFound:
    case Http::scTemporaryRedirect:
        if (rep->date <= 0)
            decision.make(ReuseDecision::doNotCacheButShare, "Date is missing/invalid");
        else if (rep->expires > rep->date)
            decision.make(ReuseDecision::cachePositively, "Expires > Date");
        else
            decision.make(ReuseDecision::doNotCacheButShare, "Expires <= Date");
        break;

    /* These responses can be negatively cached. Most can also be shared. */
    case Http::scNoContent:
    case Http::scUseProxy:
    case Http::scForbidden:
    case Http::scNotFound:
    case Http::scMethodNotAllowed:
    case Http::scUriTooLong:
    case Http::scInternalServerError:
    case Http::scNotImplemented:
    case Http::scBadGateway:
    case Http::scServiceUnavailable:
    case Http::scGatewayTimeout:
    case Http::scMisdirectedRequest:
        statusAnswer = ReuseDecision::doNotCacheButShare;
        statusReason = shareableError;
        [[fallthrough]]; // to the actual decision making below

    case Http::scBadRequest: // no sharing; perhaps the server did not like something specific to this request
#if USE_HTTP_VIOLATIONS
        if (Config.negativeTtl > 0)
            decision.make(ReuseDecision::cacheNegatively, "Config.negativeTtl > 0");
        else
#endif
            decision.make(statusAnswer, statusReason);
        break;

    /* these responses can never be cached, some
       of them can be shared though */
    case Http::scSeeOther:
    case Http::scNotModified:
    case Http::scUnauthorized:
    case Http::scProxyAuthenticationRequired:
    case Http::scPaymentRequired:
    case Http::scInsufficientStorage:
        // TODO: use more specific reason for non-error status codes
        decision.make(ReuseDecision::doNotCacheButShare, shareableError);
        break;

    case Http::scPartialContent: /* Not yet supported. TODO: make shareable for suitable ranges */
    case Http::scNotAcceptable:
    case Http::scRequestTimeout: // TODO: is this shareable?
    case Http::scConflict: // TODO: is this shareable?
    case Http::scLengthRequired:
    case Http::scPreconditionFailed:
    case Http::scContentTooLarge:
    case Http::scUnsupportedMediaType:
    case Http::scUnprocessableEntity:
    case Http::scLocked: // TODO: is this shareable?
    case Http::scFailedDependency:
    case Http::scRequestedRangeNotSatisfied:
    case Http::scExpectationFailed:
    case Http::scInvalidHeader: /* Squid header parsing error */
    case Http::scHeaderTooLarge:
        decision.make(ReuseDecision::reuseNot, nonShareableError);
        break;

    default:
        /* RFC 2616 section 6.1.1: an unrecognized response MUST NOT be cached. */
        decision.make(ReuseDecision::reuseNot, "unknown status code");
        break;
    }

    return decision.answer;
}

/// assemble a variant key (vary-mark) from the given Vary header and HTTP request
static void
assembleVaryKey(String &vary, SBuf &vstr, const HttpRequest &request)
{
    static const SBuf asterisk("*");
    const char *pos = nullptr;
    const char *item = nullptr;
    int ilen = 0;

    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
        SBuf name(item, ilen);
        if (name == asterisk) {
            vstr = asterisk;
            break;
        }
        name.toLower();
        if (!vstr.isEmpty())
            vstr.append(", ", 2);
        vstr.append(name);
        String hdr(request.header.getByName(name));
        const char *value = hdr.termedBuf();
        if (value) {
            value = rfc1738_escape_part(value);
            vstr.append("=\"", 2);
            vstr.append(value);
            vstr.append("\"", 1);
        }

        hdr.clean();
    }
}

/*
 * For Vary, store the relevant request headers as
 * virtual headers in the reply
 * Returns an empty SBuf if the variance cannot be stored
 */
SBuf
httpMakeVaryMark(HttpRequest * request, HttpReply const * reply)
{
    SBuf vstr;
    String vary;

    vary = reply->header.getList(Http::HdrType::VARY);
    assembleVaryKey(vary, vstr, *request);

#if X_ACCELERATOR_VARY
    vary.clean();
    vary = reply->header.getList(Http::HdrType::HDR_X_ACCELERATOR_VARY);
    assembleVaryKey(vary, vstr, *request);
#endif

    debugs(11, 3, vstr);
    return vstr;
}

void
HttpStateData::keepaliveAccounting(HttpReply *reply)
{
    if (flags.keepalive)
        if (flags.peering && !flags.tunneling)
            ++ _peer->stats.n_keepalives_sent;

    if (reply->keep_alive) {
        if (flags.peering && !flags.tunneling)
            ++ _peer->stats.n_keepalives_recv;

        if (Config.onoff.detect_broken_server_pconns
                && reply->bodySize(request->method) == -1 && !flags.chunked) {
            debugs(11, DBG_IMPORTANT, "keepaliveAccounting: Impossible keep-alive header from '" << entry->url() << "'" );
            // debugs(11, 2, "GOT HTTP REPLY HDR:\n---------\n" << readBuf->content() << "\n----------" );
            flags.keepalive_broken = true;
        }
    }
}

void
HttpStateData::checkDateSkew(HttpReply *reply)
{
    if (reply->date > -1 && flags.toOrigin) {
        int skew = abs((int)(reply->date - squid_curtime));

        if (skew > 86400)
            debugs(11, 3, "" << request->url.host() << "'s clock is skewed by " << skew << " seconds!");
    }
}

/**
 * This creates the error page itself.. its likely
 * that the forward ported reply header max size patch
 * generates non http conformant error pages - in which
 * case the errors where should be 'BAD_GATEWAY' etc
 */
void
HttpStateData::processReplyHeader()
{
    /** Creates a blank header. If this routine is made incremental, this will not do */

    debugs(11, 3, "processReplyHeader: key '" << entry->getMD5Text() << "'");

    assert(!flags.headers_parsed);

    if (!inBuf.length())
        return;

    /* Attempt to parse the first line; this will define where the protocol, status, reason-phrase and header begin */
    {
        if (hp == nullptr)
            hp = new Http1::ResponseParser;

        bool parsedOk = hp->parse(inBuf);
        // remember the actual received status-code before returning on errors,
        // overwriting any previously stored value from earlier forwarding attempts
        request->hier.peer_reply_status = hp->messageStatus(); // may still be scNone

        // sync the buffers after parsing.
        inBuf = hp->remaining();

        if (hp->needsMoreData()) {
            if (eof) { // no more data coming
                assert(!parsedOk);
                // fall through to handle this premature EOF as an error
            } else {
                debugs(33, 5, "Incomplete response, waiting for end of response headers");
                return;
            }
        }

        if (!parsedOk) {
            // unrecoverable parsing error
            // TODO: Use Raw! XXX: inBuf no longer has the [beginning of the] malformed header.
            debugs(11, 3, "Non-HTTP-compliant header:\n---------\n" << inBuf << "\n----------");
            flags.headers_parsed = true;
            HttpReply *newrep = new HttpReply;
            // hp->needsMoreData() means hp->parseStatusCode is unusable, but, here,
            // it also means that the reply header got truncated by a premature EOF
            assert(!hp->needsMoreData() || eof);
            const auto scode = hp->needsMoreData() ? Http::scInvalidHeader : hp->parseStatusCode;
            newrep->sline.set(Http::ProtocolVersion(), scode);
            setVirginReply(newrep);
            return;
        }
    }

    /* We know the whole response is in parser now */
    debugs(11, 2, "HTTP Server " << serverConnection);
    debugs(11, 2, "HTTP Server RESPONSE:\n---------\n" <<
           hp->messageProtocol() << " " << hp->messageStatus() << " " << hp->reasonPhrase() << "\n" <<
           hp->mimeHeader() <<
           "----------");

    // reset payload tracking to begin after message headers
    payloadSeen = inBuf.length();

    const auto newrep = HttpReply::Pointer::Make();
    // XXX: RFC 7230 indicates we MAY ignore the reason phrase,
    //      and use an empty string on unknown status.
    //      We do that now to avoid performance regression from using SBuf::c_str()
    newrep->sline.set(hp->messageProtocol(), hp->messageStatus() /* , hp->reasonPhrase() */);

    // parse headers
    if (!newrep->parseHeader(*hp)) {
        newrep->sline.set(hp->messageProtocol(), Http::scInvalidHeader);
        debugs(11, 2, "error parsing response headers mime block");
    }

    // done with Parser, now process using the HttpReply
    hp = nullptr;

    newrep->sources |= request->url.getScheme() == AnyP::PROTO_HTTPS ? Http::Message::srcHttps : Http::Message::srcHttp;

    if (newrep->sline.version.protocol == AnyP::PROTO_HTTP && Http::Is1xx(newrep->sline.status())) {
        handle1xx(newrep.getRaw());
        return;
    }

    flags.chunked = false;
    if (newrep->sline.version.protocol == AnyP::PROTO_HTTP && newrep->header.chunked()) {
        flags.chunked = true;
        httpChunkDecoder = new Http1::TeChunkedParser;
    }

    if (!peerSupportsConnectionPinning())
        request->flags.connectionAuthDisabled = true;

    const auto vrep = setVirginReply(newrep.getRaw());
    flags.headers_parsed = true;

    keepaliveAccounting(vrep);

    checkDateSkew(vrep);

    processSurrogateControl (vrep);
}

/// ignore or start forwarding the 1xx response (a.k.a., control message)
void
HttpStateData::handle1xx(const HttpReply::Pointer &reply)
{
    if (fwd->al)
        fwd->al->reply = reply;

    // one 1xx at a time: we must not be called while waiting for previous 1xx
    Must(!flags.handling1xx);
    flags.handling1xx = true;

    const auto statusCode = reply->sline.status();

    // drop1xx() needs to handle HTTP 101 (Switching Protocols) responses
    // specially because they indicate that the server has stopped speaking HTTP
    Must(!flags.serverSwitchedProtocols);
    flags.serverSwitchedProtocols = (statusCode == Http::scSwitchingProtocols);

    if (statusCode == Http::scContinue && request->forcedBodyContinuation)
        return drop1xx("we have sent it already");

    if (!request->canHandle1xx())
        return drop1xx("the client does not support it");

#if USE_HTTP_VIOLATIONS
    // check whether the 1xx response forwarding is allowed by squid.conf
    if (Config.accessList.reply) {
        ACLFilledChecklist ch(Config.accessList.reply, originalRequest().getRaw());
        ch.updateAle(fwd->al);
        ch.updateReply(reply);
        ch.syncAle(originalRequest().getRaw(), nullptr);
        if (!ch.fastCheck().allowed()) // TODO: support slow lookups?
            return drop1xx("http_reply_access blocked it");
    }
#endif // USE_HTTP_VIOLATIONS

    if (flags.serverSwitchedProtocols) {
        if (const auto reason = blockSwitchingProtocols(*reply))
            return drop1xx(reason);
    }

    debugs(11, 2, "forwarding 1xx to client");

    // the Sink will use this to call us back after writing 1xx to the client
    typedef NullaryMemFunT<HttpStateData> CbDialer;
    const AsyncCall::Pointer cb = JobCallback(11, 3, CbDialer, this,
                                  HttpStateData::proceedAfter1xx);
    CallJobHere1(11, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::sendControlMsg, HttpControlMsg(reply, cb));
    // If the call is not fired, then the Sink is gone, and HttpStateData
    // will terminate due to an aborted store entry or another similar error.
    // If we get stuck, it is not handle1xx fault if we could get stuck
    // for similar reasons without a 1xx response.
}

/// if possible, safely ignores the received 1xx control message
/// otherwise, terminates the server connection
void
HttpStateData::drop1xx(const char *reason)
{
    if (flags.serverSwitchedProtocols) {
        debugs(11, 2, "bad 101 because " << reason);
        const auto err = new ErrorState(ERR_INVALID_RESP, Http::scBadGateway, request.getRaw(), fwd->al);
        fwd->fail(err);
        closeServer();
        mustStop("prohibited HTTP/101 response");
        return;
    }

    debugs(11, 2, "ignoring 1xx because " << reason);
    proceedAfter1xx();
}

/// \retval nil if the HTTP/101 (Switching Protocols) reply should be forwarded
/// \retval reason why an attempt to switch protocols should be stopped
const char *
HttpStateData::blockSwitchingProtocols(const HttpReply &reply) const
{
    if (!upgradeHeaderOut)
        return "Squid offered no Upgrade at all, but server switched to a tunnel";

    // See RFC 7230 section 6.7 for the corresponding MUSTs

    if (!reply.header.has(Http::HdrType::UPGRADE))
        return "server did not send an Upgrade header field";

    if (!reply.header.hasListMember(Http::HdrType::CONNECTION, "upgrade", ','))
        return "server did not send 'Connection: upgrade'";

    const auto acceptedProtos = reply.header.getList(Http::HdrType::UPGRADE);
    const char *pos = nullptr;
    const char *accepted = nullptr;
    int acceptedLen = 0;
    while (strListGetItem(&acceptedProtos, ',', &accepted, &acceptedLen, &pos)) {
        debugs(11, 5, "server accepted at least" << Raw(nullptr, accepted, acceptedLen));
        return nullptr; // OK: let the client validate server's selection
    }

    return "server sent an essentially empty Upgrade header field";
}

/// restores state and resumes processing after 1xx is ignored or forwarded
void
HttpStateData::proceedAfter1xx()
{
    Must(flags.handling1xx);

    if (flags.serverSwitchedProtocols) {
        // pass server connection ownership to request->clientConnectionManager
        ConnStateData::ServerConnectionContext scc(serverConnection, inBuf);
        typedef UnaryMemFunT<ConnStateData, ConnStateData::ServerConnectionContext> MyDialer;
        AsyncCall::Pointer call = asyncCall(11, 3, "ConnStateData::noteTakeServerConnectionControl",
                                            MyDialer(request->clientConnectionManager,
                                                    &ConnStateData::noteTakeServerConnectionControl, scc));
        ScheduleCallHere(call);
        fwd->unregister(serverConnection);
        comm_remove_close_handler(serverConnection->fd, closeHandler);
        closeHandler = nullptr;
        serverConnection = nullptr;
        doneWithFwd = "switched protocols";
        mustStop(doneWithFwd);
        return;
    }

    debugs(11, 2, "continuing with " << payloadSeen << " bytes in buffer after 1xx");
    CallJobHere(11, 3, this, HttpStateData, HttpStateData::processReply);
}

/**
 * returns true if the peer can support connection pinning
*/
bool
HttpStateData::peerSupportsConnectionPinning() const
{
    if (!_peer)
        return true;

    // we are talking "through" rather than "to" our _peer
    if (flags.tunneling)
        return true;

    /*If this peer does not support connection pinning (authenticated
      connections) return false
     */
    if (!_peer->connection_auth)
        return false;

    const auto &rep = entry->mem().freshestReply();

    /*The peer supports connection pinning and the http reply status
      is not unauthorized, so the related connection can be pinned
     */
    if (rep.sline.status() != Http::scUnauthorized)
        return true;

    /*The server respond with Http::scUnauthorized and the peer configured
      with "connection-auth=on" we know that the peer supports pinned
      connections
    */
    if (_peer->connection_auth == 1)
        return true;

    /*At this point peer has configured with "connection-auth=auto"
      parameter so we need some extra checks to decide if we are going
      to allow pinned connections or not
    */

    /*if the peer configured with originserver just allow connection
        pinning (squid 2.6 behaviour)
     */
    if (_peer->options.originserver)
        return true;

    /*if the connections it is already pinned it is OK*/
    if (request->flags.pinned)
        return true;

    /*Allow pinned connections only if the Proxy-support header exists in
      reply and has in its list the "Session-Based-Authentication"
      which means that the peer supports connection pinning.
     */
    if (rep.header.hasListMember(Http::HdrType::PROXY_SUPPORT, "Session-Based-Authentication", ','))
        return true;

    return false;
}

// Called when we parsed (and possibly adapted) the headers but
// had not starting storing (a.k.a., sending) the body yet.
void
HttpStateData::haveParsedReplyHeaders()
{
    Client::haveParsedReplyHeaders();

    HttpReply *rep = finalReply();
    const Http::StatusCode statusCode = rep->sline.status();

    entry->timestampsSet();

    /* Check if object is cacheable or not based on reply code */
    debugs(11, 3, "HTTP CODE: " << statusCode);

    if (StoreEntry *oldEntry = findPreviouslyCachedEntry(entry)) {
        oldEntry->lock("HttpStateData::haveParsedReplyHeaders");
        sawDateGoBack = rep->olderThan(oldEntry->hasFreshestReply());
        oldEntry->unlock("HttpStateData::haveParsedReplyHeaders");
    }

    if (neighbors_do_private_keys && !sawDateGoBack)
        httpMaybeRemovePublic(entry, rep->sline.status());

    bool varyFailure = false;
    if (rep->header.has(Http::HdrType::VARY)
#if X_ACCELERATOR_VARY
            || rep->header.has(Http::HdrType::HDR_X_ACCELERATOR_VARY)
#endif
       ) {
        const SBuf vary(httpMakeVaryMark(request.getRaw(), rep));

        if (vary.isEmpty()) {
            // TODO: check whether such responses are shareable.
            // Do not share for now.
            entry->makePrivate(false);
            if (Http::IsReforwardableStatus(rep->sline.status()))
                EBIT_SET(entry->flags, ENTRY_FWD_HDR_WAIT);
            varyFailure = true;
        } else {
            entry->mem_obj->vary_headers = vary;

            // RFC 7231 section 7.1.4
            // Vary:* can be cached, but has mandatory revalidation
            static const SBuf asterisk("*");
            if (vary == asterisk)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_ALWAYS);
        }
    }

    if (!varyFailure) {
        /*
         * If its not a reply that we will re-forward, then
         * allow the client to get it.
         */
        if (Http::IsReforwardableStatus(rep->sline.status()))
            EBIT_SET(entry->flags, ENTRY_FWD_HDR_WAIT);

        ReuseDecision decision(entry, statusCode);

        switch (reusableReply(decision)) {

        case ReuseDecision::reuseNot:
            entry->makePrivate(false);
            break;

        case ReuseDecision::cachePositively:
            if (!entry->makePublic()) {
                decision.make(ReuseDecision::doNotCacheButShare, "public key creation error");
                entry->makePrivate(true);
            }
            break;

        case ReuseDecision::cacheNegatively:
            if (!entry->cacheNegatively()) {
                decision.make(ReuseDecision::doNotCacheButShare, "public key creation error");
                entry->makePrivate(true);
            }
            break;

        case ReuseDecision::doNotCacheButShare:
            entry->makePrivate(true);
            break;

        default:
            assert(0);
            break;
        }
        debugs(11, 3, "decided: " << decision);
    }

    if (!ignoreCacheControl) {
        if (rep->cache_control) {
            // We are required to revalidate on many conditions.
            // For security reasons we do so even if storage was caused by refresh_pattern ignore-* option

            // CC:must-revalidate or CC:proxy-revalidate
            const bool ccMustRevalidate = (rep->cache_control->hasProxyRevalidate() || rep->cache_control->hasMustRevalidate());

            // CC:no-cache (only if there are no parameters)
            const bool ccNoCacheNoParams = rep->cache_control->hasNoCacheWithoutParameters();

            // CC:s-maxage=N
            const bool ccSMaxAge = rep->cache_control->hasSMaxAge();

            // CC:private (yes, these can sometimes be stored)
            const bool ccPrivate = rep->cache_control->hasPrivate();

            if (ccNoCacheNoParams || ccPrivate)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_ALWAYS);
            else if (ccMustRevalidate || ccSMaxAge)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_STALE);
        }
#if USE_HTTP_VIOLATIONS // response header Pragma::no-cache is undefined in HTTP
        else {
            // Expensive calculation. So only do it IF the CC: header is not present.

            /* HACK: Pragma: no-cache in _replies_ is not documented in HTTP,
             * but servers like "Active Imaging Webcast/2.0" sure do use it */
            if (rep->header.has(Http::HdrType::PRAGMA) &&
                    rep->header.hasListMember(Http::HdrType::PRAGMA,"no-cache",','))
                EBIT_SET(entry->flags, ENTRY_REVALIDATE_ALWAYS);
        }
#endif
    }
}

HttpStateData::ConnectionStatus
HttpStateData::statusIfComplete() const
{
    const HttpReply *rep = virginReply();
    /** \par
     * If the reply wants to close the connection, it takes precedence */

    static SBuf close("close", 5);
    if (httpHeaderHasConnDir(&rep->header, close))
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we sent a Connection:close request header, then this
     * can not be a persistent connection.
     */
    if (!flags.keepalive)
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we banned reuse, then this cannot be a persistent connection.
     */
    if (flags.forceClose)
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we haven't sent the whole request then this can not be a persistent
     * connection.
     */
    if (!flags.request_sent) {
        debugs(11, 2, "Request not yet fully sent " << request->method << ' ' << entry->url());
        return COMPLETE_NONPERSISTENT_MSG;
    }

    /** \par
     * What does the reply have to say about keep-alive?
     */
    /* XXX: BUG?
     * If the origin server (HTTP/1.0) does not send a keep-alive
     * header, but keeps the connection open anyway, what happens?
     * We'll return here and wait for an EOF before changing
     * store_status to STORE_OK.   Combine this with ENTRY_FWD_HDR_WAIT
     * and an error status code, and we might have to wait until
     * the server times out the socket.
     */
    if (!rep->keep_alive)
        return COMPLETE_NONPERSISTENT_MSG;

    return COMPLETE_PERSISTENT_MSG;
}

HttpStateData::ConnectionStatus
HttpStateData::persistentConnStatus() const
{
    debugs(11, 3, serverConnection << " eof=" << eof);
    if (eof) // already reached EOF
        return COMPLETE_NONPERSISTENT_MSG;

    /* If server fd is closing (but we have not been notified yet), stop Comm
       I/O to avoid assertions. TODO: Change Comm API to handle callers that
       want more I/O after async closing (usually initiated by others). */
    // XXX: add canReceive or s/canSend/canTalkToServer/
    if (!Comm::IsConnOpen(serverConnection))
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * In chunked response we do not know the content length but we are absolutely
     * sure about the end of response, so we are calling the statusIfComplete to
     * decide if we can be persistent
     */
    if (lastChunk && flags.chunked)
        return statusIfComplete();

    const HttpReply *vrep = virginReply();
    debugs(11, 5, "persistentConnStatus: content_length=" << vrep->content_length);

    const int64_t clen = vrep->bodySize(request->method);

    debugs(11, 5, "persistentConnStatus: clen=" << clen);

    /* If the body size is unknown we must wait for EOF */
    if (clen < 0)
        return INCOMPLETE_MSG;

    /** \par
     * If the body size is known, we must wait until we've gotten all of it. */
    if (clen > 0) {
        debugs(11,5, "payloadSeen=" << payloadSeen << " content_length=" << vrep->content_length);

        if (payloadSeen < vrep->content_length)
            return INCOMPLETE_MSG;

        if (payloadTruncated > 0) // already read more than needed
            return COMPLETE_NONPERSISTENT_MSG; // disable pconns
    }

    /** \par
     * If there is no message body or we got it all, we can be persistent */
    return statusIfComplete();
}

void
HttpStateData::noteDelayAwareReadChance()
{
    waitingForDelayAwareReadChance = false;
    maybeReadVirginBody();
}

void
HttpStateData::readReply(const CommIoCbParams &io)
{
    debugs(11, 5, io.conn);
    waitingForCommRead = false;

    // Bail out early on Comm::ERR_CLOSING - close handlers will tidy up for us
    if (io.flag == Comm::ERR_CLOSING) {
        debugs(11, 3, "http socket closing");
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("store entry aborted while reading reply");
        return;
    }

    Must(Comm::IsConnOpen(serverConnection));
    Must(io.conn->fd == serverConnection->fd);

    /*
     * Don't reset the timeout value here. The value should be
     * counting Config.Timeout.request and applies to the request
     * as a whole, not individual read() calls.
     * Plus, it breaks our lame *HalfClosed() detection
     */

    const auto moreDataPermission = canBufferMoreReplyBytes();
    if (!moreDataPermission) {
        abortTransaction("ready to read required data, but the read buffer is full and cannot be drained");
        return;
    }

    const auto readSizeMax = maybeMakeSpaceAvailable(moreDataPermission.value());
    // TODO: Move this logic inside maybeMakeSpaceAvailable():
    const auto readSizeWanted = readSizeMax ? entry->bytesWanted(Range<size_t>(0, readSizeMax)) : 0;

    if (readSizeWanted <= 0) {
        // XXX: If we avoid Comm::ReadNow(), we should not Comm::Read() again
        // when the wait is over. We should go straight to readReply() instead.

#if USE_ADAPTATION
        // XXX: We are duplicating Client::calcBufferSpaceToReserve() logic.
        // XXX: Some other delayRead() cases may lack kickReads() guarantees.
        // TODO: Refactor maybeMakeSpaceAvailable() to properly treat each
        // no-read case instead of calling delayRead() for the remaining cases.

        if (responseBodyBuffer) {
            debugs(11, 5, "avoid delayRead() to give adaptation a chance to drain overflow buffer: " << responseBodyBuffer->contentSize());
            return; // wait for Client::noteMoreBodySpaceAvailable()
        }

        if (virginBodyDestination && !virginBodyDestination->buf().hasPotentialSpace()) {
            debugs(11, 5, "avoid delayRead() to give adaptation a chance to drain body pipe buffer: " << virginBodyDestination->buf().contentSize());
            return; // wait for Client::noteMoreBodySpaceAvailable()
        }
#endif

        delayRead(); /// wait for Client::noteDelayAwareReadChance()
        return;
    }

    CommIoCbParams rd(this); // will be expanded with ReadNow results
    rd.conn = io.conn;
    rd.size = readSizeWanted;
    switch (Comm::ReadNow(rd, inBuf)) {
    case Comm::INPROGRESS:
        if (inBuf.isEmpty())
            debugs(33, 2, io.conn << ": no data to process, " << xstrerr(rd.xerrno));
        maybeReadVirginBody();
        return;

    case Comm::OK:
    {
        payloadSeen += rd.size;
#if USE_DELAY_POOLS
        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(rd.size);
#endif

        statCounter.server.all.kbytes_in += rd.size;
        statCounter.server.http.kbytes_in += rd.size;
        ++ IOStats.Http.reads;

        int bin = 0;
        for (int clen = rd.size - 1; clen; ++bin)
            clen >>= 1;

        ++ IOStats.Http.read_hist[bin];

        request->hier.notePeerRead();
    }

        /* Continue to process previously read data */
    break;

    case Comm::ENDFILE: // close detected by 0-byte read
        eof = 1;

        /* Continue to process previously read data */
        break;

    // case Comm::COMM_ERROR:
    default: // no other flags should ever occur
        debugs(11, 2, io.conn << ": read failure: " << xstrerr(rd.xerrno));
        const auto err = new ErrorState(ERR_READ_ERROR, Http::scBadGateway, fwd->request, fwd->al);
        err->xerrno = rd.xerrno;
        fwd->fail(err);
        closeServer();
        mustStop("HttpStateData::readReply");
        return;
    }

    /* Process next response from buffer */
    processReply();
}

/// processes the already read and buffered response data, possibly after
/// waiting for asynchronous 1xx control message processing
void
HttpStateData::processReply()
{

    if (flags.handling1xx) { // we came back after handling a 1xx response
        debugs(11, 5, "done with 1xx handling");
        flags.handling1xx = false;
        Must(!flags.headers_parsed);
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("store entry aborted while we were waiting for processReply()");
        return;
    }

    if (!flags.headers_parsed) { // have not parsed headers yet?
        processReplyHeader();

        if (!continueAfterParsingHeader()) // parsing error or need more data
            return; // TODO: send errors to ICAP

        adaptOrFinalizeReply(); // may write to, abort, or "close" the entry
    }

    // kick more reads if needed and/or process the response body, if any
    processReplyBody(); // may call serverComplete()
}

/**
 \retval true    if we can continue with processing the body or doing ICAP.
 */
bool
HttpStateData::continueAfterParsingHeader()
{
    if (flags.handling1xx) {
        debugs(11, 5, "wait for 1xx handling");
        Must(!flags.headers_parsed);
        return false;
    }

    if (!flags.headers_parsed && !eof) {
        debugs(11, 9, "needs more at " << inBuf.length());
        /** \retval false If we have not finished parsing the headers and may get more data.
         *                Schedules more reads to retrieve the missing data.
         */
        maybeReadVirginBody(); // schedules all kinds of reads; TODO: rename
        return false;
    }

    /** If we are done with parsing, check for errors */

    err_type error = ERR_NONE;

    if (flags.headers_parsed) { // parsed headers, possibly with errors
        // check for header parsing errors
        if (HttpReply *vrep = virginReply()) {
            const Http::StatusCode s = vrep->sline.status();
            const AnyP::ProtocolVersion &v = vrep->sline.version;
            if (s == Http::scInvalidHeader && v != Http::ProtocolVersion(0,9)) {
                debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: Bad header encountered from " << entry->url() << " AKA " << request->url);
                error = ERR_INVALID_RESP;
            } else if (s == Http::scHeaderTooLarge) {
                fwd->dontRetry(true);
                error = ERR_TOO_BIG;
            } else if (vrep->header.conflictingContentLength()) {
                fwd->dontRetry(true);
                error = ERR_INVALID_RESP;
            } else if (vrep->header.unsupportedTe()) {
                fwd->dontRetry(true);
                error = ERR_INVALID_RESP;
            } else {
                return true; // done parsing, got reply, and no error
            }
        } else {
            // parsed headers but got no reply
            debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: No reply at all for " << entry->url() << " AKA " << request->url);
            error = ERR_INVALID_RESP;
        }
    } else {
        assert(eof);
        if (inBuf.length()) {
            error = ERR_INVALID_RESP;
            debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: Headers did not parse at all for " << entry->url() << " AKA " << request->url);
        } else {
            error = ERR_ZERO_SIZE_OBJECT;
            debugs(11, (request->flags.accelerated?DBG_IMPORTANT:2), "WARNING: HTTP: Invalid Response: No object data received for " << entry->url() << " AKA " << request->url);
        }
    }

    assert(error != ERR_NONE);
    entry->reset();
    fwd->fail(new ErrorState(error, Http::scBadGateway, fwd->request, fwd->al));
    closeServer();
    mustStop("HttpStateData::continueAfterParsingHeader");
    return false; // quit on error
}

/** truncate what we read if we read too much so that writeReplyBody()
    writes no more than what we should have read */
void
HttpStateData::truncateVirginBody()
{
    assert(flags.headers_parsed);

    HttpReply *vrep = virginReply();
    int64_t clen = -1;
    if (!vrep->expectingBody(request->method, clen) || clen < 0)
        return; // no body or a body of unknown size, including chunked

    if (payloadSeen - payloadTruncated <= clen)
        return; // we did not read too much or already took care of the extras

    if (const int64_t extras = payloadSeen - payloadTruncated - clen) {
        // server sent more that the advertised content length
        debugs(11, 5, "payloadSeen=" << payloadSeen <<
               " clen=" << clen << '/' << vrep->content_length <<
               " truncated=" << payloadTruncated << '+' << extras);

        inBuf.chop(0, inBuf.length() - extras);
        payloadTruncated += extras;
    }
}

/// called on a premature EOF discovered when reading response body
void
HttpStateData::markPrematureReplyBodyEofFailure()
{
    const auto err = new ErrorState(ERR_READ_ERROR, Http::scBadGateway, fwd->request, fwd->al);
    static const auto d = MakeNamedErrorDetail("SRV_PREMATURE_EOF");
    err->detailError(d);
    fwd->fail(err);
}

/**
 * Call this when there is data from the origin server
 * which should be sent to either StoreEntry, or to ICAP...
 */
void
HttpStateData::writeReplyBody()
{
    truncateVirginBody(); // if needed
    const char *data = inBuf.rawContent();
    int len = inBuf.length();
    addVirginReplyBody(data, len);
    inBuf.consume(len);

    // after addVirginReplyBody() wrote (when not adapting) everything we have
    // received to Store, check whether we have received/parsed the entire reply
    int64_t clen = -1;
    const char *parsedWhole = nullptr;
    if (!virginReply()->expectingBody(request->method, clen))
        parsedWhole = "http parsed header-only reply";
    else if (clen >= 0 && clen == payloadSeen - payloadTruncated)
        parsedWhole = "http parsed Content-Length body bytes";
    else if (clen < 0 && eof)
        parsedWhole = "http parsed body ending with expected/required EOF";

    if (parsedWhole)
        markParsedVirginReplyAsWhole(parsedWhole);
    else if (eof)
        markPrematureReplyBodyEofFailure();
}

bool
HttpStateData::decodeAndWriteReplyBody()
{
    assert(flags.chunked);
    assert(httpChunkDecoder);
    try {
        MemBuf decodedData;
        decodedData.init();
        httpChunkDecoder->setPayloadBuffer(&decodedData);
        const bool doneParsing = httpChunkDecoder->parse(inBuf);
        inBuf = httpChunkDecoder->remaining(); // sync buffers after parse
        addVirginReplyBody(decodedData.content(), decodedData.contentSize());
        if (doneParsing) {
            lastChunk = 1;
            markParsedVirginReplyAsWhole("http parsed last-chunk");
        } else if (eof) {
            markPrematureReplyBodyEofFailure();
        }
        return true;
    }
    catch (...) {
        debugs (11, 2, "de-chunking failure: " << CurrentException);
    }
    return false;
}

/**
 * processReplyBody has two purposes:
 *  1 - take the reply body data, if any, and put it into either
 *      the StoreEntry, or give it over to ICAP.
 *  2 - see if we made it to the end of the response (persistent
 *      connections and such)
 */
void
HttpStateData::processReplyBody()
{
    if (!flags.headers_parsed) {
        maybeReadVirginBody();
        return;
    }

#if USE_ADAPTATION
    debugs(11,5, "adaptationAccessCheckPending=" << adaptationAccessCheckPending);
    if (adaptationAccessCheckPending)
        return;

#endif

    /*
     * At this point the reply headers have been parsed and consumed.
     * That means header content has been removed from readBuf and
     * it contains only body data.
     */
    if (entry->isAccepting()) {
        if (flags.chunked) {
            if (!decodeAndWriteReplyBody()) {
                serverComplete();
                return;
            }
        } else
            writeReplyBody();
    }

    // storing/sending methods like earlier adaptOrFinalizeReply() or
    // above writeReplyBody() may release/abort the store entry.
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        // TODO: In some cases (e.g., 304), we should keep persistent conn open.
        // Detect end-of-reply (and, hence, pool our idle pconn) earlier (ASAP).
        abortTransaction("store entry aborted while storing reply");
        return;
    } else
        switch (persistentConnStatus()) {
        case INCOMPLETE_MSG: {
            debugs(11, 5, "processReplyBody: INCOMPLETE_MSG from " << serverConnection);
            /* Wait for more data or EOF condition */
            AsyncCall::Pointer nil;
            if (flags.keepalive_broken) {
                commSetConnTimeout(serverConnection, 10, nil);
            } else {
                commSetConnTimeout(serverConnection, Config.Timeout.read, nil);
            }
        }
        break;

        case COMPLETE_PERSISTENT_MSG: {
            debugs(11, 5, "processReplyBody: COMPLETE_PERSISTENT_MSG from " << serverConnection);

            // TODO: Remove serverConnectionSaved but preserve exception safety.

            commUnsetConnTimeout(serverConnection);

            comm_remove_close_handler(serverConnection->fd, closeHandler);
            closeHandler = nullptr;

            Ip::Address client_addr; // XXX: Remove as unused. Why was it added?
            if (request->flags.spoofClientIp)
                client_addr = request->client_addr;

            auto serverConnectionSaved = serverConnection;
            fwd->unregister(serverConnection);
            serverConnection = nullptr;

            bool ispinned = false; // TODO: Rename to isOrShouldBePinned
            if (request->flags.pinned) {
                ispinned = true;
            } else if (request->flags.connectionAuth && request->flags.authSent) {
                ispinned = true;
            }

            if (ispinned) {
                if (request->clientConnectionManager.valid()) {
                    CallJobHere1(11, 4, request->clientConnectionManager,
                                 ConnStateData,
                                 notePinnedConnectionBecameIdle,
                                 ConnStateData::PinnedIdleContext(serverConnectionSaved, request));
                } else {
                    // must not pool/share ispinned connections, even orphaned ones
                    serverConnectionSaved->close();
                }
            } else {
                fwdPconnPool->push(serverConnectionSaved, request->url.host());
            }

            serverComplete();
            return;
        }

        case COMPLETE_NONPERSISTENT_MSG:
            debugs(11, 5, "processReplyBody: COMPLETE_NONPERSISTENT_MSG from " << serverConnection);

            serverComplete();
            return;
        }

    maybeReadVirginBody();
}

bool
HttpStateData::mayReadVirginReplyBody() const
{
    // TODO: Be more precise here. For example, if/when reading trailer, we may
    // not be doneWithServer() yet, but we should return false. Similarly, we
    // could still be writing the request body after receiving the whole reply.
    return !doneWithServer();
}

void
HttpStateData::maybeReadVirginBody()
{
    if (!Comm::IsConnOpen(serverConnection) || fd_table[serverConnection->fd].closing()) {
        debugs(11, 3, "no, peer connection gone");
        return;
    }

    if (eof) {
        // tolerate hypothetical calls between Comm::ENDFILE and closeServer()
        debugs(11, 3, "no, saw EOF");
        return;
    }

    if (lastChunk) {
        // tolerate hypothetical calls between setting lastChunk and clearing serverConnection
        debugs(11, 3, "no, saw last-chunk");
        return;
    }

    if (!canBufferMoreReplyBytes()) {
        abortTransaction("more response bytes required, but the read buffer is full and cannot be drained");
        return;
    }

    if (waitingForDelayAwareReadChance) {
        debugs(11, 5, "no, still waiting for noteDelayAwareReadChance()");
        return;
    }

    if (waitingForCommRead) {
        debugs(11, 3, "no, already waiting for readReply()");
        return;
    }

    assert(!Comm::MonitorsRead(serverConnection->fd));

    // wait for read(2) to be possible.
    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    AsyncCall::Pointer call = JobCallback(11, 5, Dialer, this, HttpStateData::readReply);
    Comm::Read(serverConnection, call);
    waitingForCommRead = true;
}

/// Desired inBuf capacity based on various capacity preferences/limits:
/// * a smaller buffer may not hold enough for look-ahead header/body parsers;
/// * a smaller buffer may result in inefficient tiny network reads;
/// * a bigger buffer may waste memory;
/// * a bigger buffer may exceed SBuf storage capabilities (SBuf::maxSize);
size_t
HttpStateData::calcReadBufferCapacityLimit() const
{
    if (!flags.headers_parsed)
        return Config.maxReplyHeaderSize;

    // XXX: Our inBuf is not used to maintain the read-ahead gap, and using
    // Config.readAheadGap like this creates huge read buffers for large
    // read_ahead_gap values. TODO: Switch to using tcp_recv_bufsize as the
    // primary read buffer capacity factor.
    //
    // TODO: Cannot reuse throwing NaturalCast() here. Consider removing
    // .value() dereference in NaturalCast() or add/use NaturalCastOrMax().
    const auto configurationPreferences = NaturalSum<size_t>(Config.readAheadGap).value_or(SBuf::maxSize);

    // TODO: Honor TeChunkedParser look-ahead and trailer parsing requirements
    // (when explicit configurationPreferences are set too low).

    return std::min<size_t>(configurationPreferences, SBuf::maxSize);
}

/// The maximum number of virgin reply bytes we may buffer before we violate
/// the currently configured response buffering limits.
/// \retval std::nullopt means that no more virgin response bytes can be read
/// \retval 0 means that more virgin response bytes may be read later
/// \retval >0 is the number of bytes that can be read now (subject to other constraints)
std::optional<size_t>
HttpStateData::canBufferMoreReplyBytes() const
{
#if USE_ADAPTATION
    // If we do not check this now, we may say the final "no" prematurely below
    // because inBuf.length() will decrease as adaptation drains buffered bytes.
    if (responseBodyBuffer) {
        debugs(11, 3, "yes, but waiting for adaptation to drain read buffer");
        return 0; // yes, we may be able to buffer more (but later)
    }
#endif

    const auto maxCapacity = calcReadBufferCapacityLimit();
    if (inBuf.length() >= maxCapacity) {
        debugs(11, 3, "no, due to a full buffer: " << inBuf.length() << '/' << inBuf.spaceSize() << "; limit: " << maxCapacity);
        return std::nullopt; // no, configuration prohibits buffering more
    }

    const auto maxReadSize = maxCapacity - inBuf.length(); // positive
    debugs(11, 7, "yes, may read up to " << maxReadSize << " into " << inBuf.length() << '/' << inBuf.spaceSize());
    return maxReadSize; // yes, can read up to this many bytes (subject to other constraints)
}

/// prepare read buffer for reading
/// \return the maximum number of bytes the caller should attempt to read
/// \retval 0 means that the caller should delay reading
size_t
HttpStateData::maybeMakeSpaceAvailable(const size_t maxReadSize)
{
    // how much we want to read
    const size_t read_size = calcBufferSpaceToReserve(inBuf.spaceSize(), maxReadSize);

    if (!read_size) {
        debugs(11, 7, "will not read up to " << read_size << " into buffer (" << inBuf.length() << "/" << inBuf.spaceSize() << ") from " << serverConnection);
        return 0;
    }

    // we may need to grow the buffer
    inBuf.reserveSpace(read_size);
    debugs(11, 7, "may read up to " << read_size << " bytes info buffer (" << inBuf.length() << "/" << inBuf.spaceSize() << ") from " << serverConnection);
    return read_size;
}

/// called after writing the very last request byte (body, last-chunk, etc)
void
HttpStateData::wroteLast(const CommIoCbParams &io)
{
    debugs(11, 5, serverConnection << ": size " << io.size << ": errflag " << io.flag << ".");
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    // XXX: Keep in sync with Client::sentRequestBody().
    // TODO: Extract common parts.

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, IoDirection::Write);
        statCounter.server.all.kbytes_out += io.size;
        statCounter.server.http.kbytes_out += io.size;
    }

    if (io.flag == Comm::ERR_CLOSING)
        return;

    // both successful and failed writes affect response times
    request->hier.notePeerWrite();

    if (io.flag) {
        const auto err = new ErrorState(ERR_WRITE_ERROR, Http::scBadGateway, fwd->request, fwd->al);
        err->xerrno = io.xerrno;
        fwd->fail(err);
        closeServer();
        mustStop("HttpStateData::wroteLast");
        return;
    }

    sendComplete();
}

/// successfully wrote the entire request (including body, last-chunk, etc.)
void
HttpStateData::sendComplete()
{
    /*
     * Set the read timeout here because it hasn't been set yet.
     * We only set the read timeout after the request has been
     * fully written to the peer.  If we start the timeout
     * after connection establishment, then we are likely to hit
     * the timeout for POST/PUT requests that have very large
     * request bodies.
     */
    typedef CommCbMemFunT<HttpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(11, 5,
                                      TimeoutDialer, this, HttpStateData::httpTimeout);

    commSetConnTimeout(serverConnection, Config.Timeout.read, timeoutCall);
    flags.request_sent = true;
}

void
HttpStateData::closeServer()
{
    debugs(11,5, "closing HTTP server " << serverConnection << " this " << this);

    if (Comm::IsConnOpen(serverConnection)) {
        fwd->unregister(serverConnection);
        comm_remove_close_handler(serverConnection->fd, closeHandler);
        closeHandler = nullptr;
        serverConnection->close();
    }
}

bool
HttpStateData::doneWithServer() const
{
    return !Comm::IsConnOpen(serverConnection);
}

/*
 * Fixup authentication request headers for special cases
 */
static void
httpFixupAuthentication(HttpRequest * request, const HttpHeader * hdr_in, HttpHeader * hdr_out, const CachePeer * const peer, const Http::StateFlags &flags)
{
    /* Nothing to do unless we are forwarding to a peer */
    if (!flags.peering)
        return;

    // do nothing if our cache_peer was reconfigured away
    if (!peer)
        return;

    // This request is going "through" rather than "to" our _peer.
    if (flags.tunneling)
        return;

    /* Needs to be explicitly enabled */
    if (!request->peer_login)
        return;

    const auto header = flags.toOrigin ? Http::HdrType::AUTHORIZATION : Http::HdrType::PROXY_AUTHORIZATION;
    /* Maybe already dealt with? */
    if (hdr_out->has(header))
        return;

    /* Nothing to do here for PASSTHRU */
    if (strcmp(request->peer_login, "PASSTHRU") == 0)
        return;

    // Dangerous and undocumented PROXYPASS is a single-signon to servers with
    // the proxy password. Only Basic Authentication can work this way. This
    // statement forwards a "basic" Proxy-Authorization value from our client
    // to an originserver peer. Other PROXYPASS cases are handled lower.
    if (flags.toOrigin &&
            strcmp(request->peer_login, "PROXYPASS") == 0 &&
            hdr_in->has(Http::HdrType::PROXY_AUTHORIZATION)) {

        const char *auth = hdr_in->getStr(Http::HdrType::PROXY_AUTHORIZATION);

        if (auth && strncasecmp(auth, "basic ", 6) == 0) {
            hdr_out->putStr(header, auth);
            return;
        }
    }

    char loginbuf[base64_encode_len(MAX_LOGIN_SZ)];
    size_t blen;
    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);

    /* Special mode to pass the username to the upstream cache */
    if (*request->peer_login == '*') {
        const char *username = "-";

        if (request->extacl_user.size())
            username = request->extacl_user.termedBuf();
#if USE_AUTH
        else if (request->auth_user_request != nullptr)
            username = request->auth_user_request->username();
#endif

        blen = base64_encode_update(&ctx, loginbuf, strlen(username), reinterpret_cast<const uint8_t*>(username));
        blen += base64_encode_update(&ctx, loginbuf+blen, strlen(request->peer_login +1), reinterpret_cast<const uint8_t*>(request->peer_login +1));
        blen += base64_encode_final(&ctx, loginbuf+blen);
        httpHeaderPutStrf(hdr_out, header, "Basic %.*s", (int)blen, loginbuf);
        return;
    }

    /* external_acl provided credentials */
    if (request->extacl_user.size() && request->extacl_passwd.size() &&
            (strcmp(request->peer_login, "PASS") == 0 ||
             strcmp(request->peer_login, "PROXYPASS") == 0)) {

        blen = base64_encode_update(&ctx, loginbuf, request->extacl_user.size(), reinterpret_cast<const uint8_t*>(request->extacl_user.rawBuf()));
        blen += base64_encode_update(&ctx, loginbuf+blen, 1, reinterpret_cast<const uint8_t*>(":"));
        blen += base64_encode_update(&ctx, loginbuf+blen, request->extacl_passwd.size(), reinterpret_cast<const uint8_t*>(request->extacl_passwd.rawBuf()));
        blen += base64_encode_final(&ctx, loginbuf+blen);
        httpHeaderPutStrf(hdr_out, header, "Basic %.*s", (int)blen, loginbuf);
        return;
    }
    // if no external user credentials are available to fake authentication with PASS acts like PASSTHRU
    if (strcmp(request->peer_login, "PASS") == 0)
        return;

    /* Kerberos login to peer */
#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI
    if (strncmp(request->peer_login, "NEGOTIATE",strlen("NEGOTIATE")) == 0) {
        char *Token=nullptr;
        char *PrincipalName=nullptr,*p;
        int negotiate_flags = 0;

        if ((p=strchr(request->peer_login,':')) != nullptr ) {
            PrincipalName=++p;
        }
        if (request->flags.auth_no_keytab) {
            negotiate_flags |= PEER_PROXY_NEGOTIATE_NOKEYTAB;
        }
        Token = peer_proxy_negotiate_auth(PrincipalName, peer->host, negotiate_flags);
        if (Token) {
            httpHeaderPutStrf(hdr_out, header, "Negotiate %s",Token);
        }
        return;
    }
#endif /* HAVE_KRB5 && HAVE_GSSAPI */

    blen = base64_encode_update(&ctx, loginbuf, strlen(request->peer_login), reinterpret_cast<const uint8_t*>(request->peer_login));
    blen += base64_encode_final(&ctx, loginbuf+blen);
    httpHeaderPutStrf(hdr_out, header, "Basic %.*s", (int)blen, loginbuf);
    return;
}

/*
 * build request headers and append them to a given MemBuf
 * used by buildRequestPrefix()
 * note: initialised the HttpHeader, the caller is responsible for Clean()-ing
 */
void
HttpStateData::httpBuildRequestHeader(HttpRequest * request,
                                      StoreEntry * entry,
                                      const AccessLogEntryPointer &al,
                                      HttpHeader * hdr_out,
                                      const CachePeer * const peer,
                                      const Http::StateFlags &flags)
{
    /* building buffer for complex strings */
#define BBUF_SZ (MAX_URL+32)
    LOCAL_ARRAY(char, bbuf, BBUF_SZ);
    LOCAL_ARRAY(char, ntoabuf, MAX_IPSTRLEN);
    const HttpHeader *hdr_in = &request->header;
    const HttpHeaderEntry *e = nullptr;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert (hdr_out->owner == hoRequest);

    /* use our IMS header if the cached entry has Last-Modified time */
    if (request->lastmod > -1)
        hdr_out->putTime(Http::HdrType::IF_MODIFIED_SINCE, request->lastmod);

    // Add our own If-None-Match field if the cached entry has a strong ETag.
    // copyOneHeaderFromClientsideRequestToUpstreamRequest() adds client ones.
    if (request->etag.size() > 0) {
        hdr_out->addEntry(new HttpHeaderEntry(Http::HdrType::IF_NONE_MATCH, SBuf(),
                                              request->etag.termedBuf()));
    }

    bool we_do_ranges = decideIfWeDoRanges (request);

    String strConnection (hdr_in->getList(Http::HdrType::CONNECTION));

    while ((e = hdr_in->getEntry(&pos)))
        copyOneHeaderFromClientsideRequestToUpstreamRequest(e, strConnection, request, hdr_out, we_do_ranges, flags);

    /* Abstraction break: We should interpret multipart/byterange responses
     * into offset-length data, and this works around our inability to do so.
     */
    if (!we_do_ranges && request->multipartRangeRequest()) {
        /* don't cache the result */
        request->flags.cachable.veto();
        /* pretend it's not a range request */
        request->ignoreRange("want to request the whole object");
        request->flags.isRanged = false;
    }

    hdr_out->addVia(request->http_ver, hdr_in);

    if (request->flags.accelerated) {
        /* Append Surrogate-Capabilities */
        String strSurrogate(hdr_in->getList(Http::HdrType::SURROGATE_CAPABILITY));
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0\"", Config.Accel.surrogate_id);
        strListAdd(&strSurrogate, bbuf, ',');
        hdr_out->delById(Http::HdrType::SURROGATE_CAPABILITY);
        hdr_out->putStr(Http::HdrType::SURROGATE_CAPABILITY, strSurrogate.termedBuf());
    }

    /** \pre Handle X-Forwarded-For */
    if (strcmp(opt_forwarded_for, "delete") != 0) {

        String strFwd = hdr_in->getList(Http::HdrType::X_FORWARDED_FOR);

        // Detect unreasonably long header values. And paranoidly check String
        // limits: a String ought to accommodate two reasonable-length values.
        if (strFwd.size() > 32*1024 || !strFwd.canGrowBy(strFwd.size())) {
            // There is probably a forwarding loop with Via detection disabled.
            // If we do nothing, String will assert on overflow soon.
            // TODO: Terminate all transactions with huge XFF?
            strFwd = "error";

            static int warnedCount = 0;
            if (warnedCount++ < 100) {
                const SBuf url(entry ? SBuf(entry->url()) : request->effectiveRequestUri());
                debugs(11, DBG_IMPORTANT, "WARNING: likely forwarding loop with " << url);
            }
        }

        if (strcmp(opt_forwarded_for, "on") == 0) {
            /** If set to ON - append client IP or 'unknown'. */
            if ( request->client_addr.isNoAddr() )
                strListAdd(&strFwd, "unknown", ',');
            else
                strListAdd(&strFwd, request->client_addr.toStr(ntoabuf, MAX_IPSTRLEN), ',');
        } else if (strcmp(opt_forwarded_for, "off") == 0) {
            /** If set to OFF - append 'unknown'. */
            strListAdd(&strFwd, "unknown", ',');
        } else if (strcmp(opt_forwarded_for, "transparent") == 0) {
            /** If set to TRANSPARENT - pass through unchanged. */
        } else if (strcmp(opt_forwarded_for, "truncate") == 0) {
            /** If set to TRUNCATE - drop existing list and replace with client IP or 'unknown'. */
            if ( request->client_addr.isNoAddr() )
                strFwd = "unknown";
            else
                strFwd = request->client_addr.toStr(ntoabuf, MAX_IPSTRLEN);
        }
        if (strFwd.size() > 0)
            hdr_out->putStr(Http::HdrType::X_FORWARDED_FOR, strFwd.termedBuf());
    }
    /** If set to DELETE - do not copy through. */

    /* append Host if not there already */
    if (!hdr_out->has(Http::HdrType::HOST)) {
        if (request->peer_domain) {
            hdr_out->putStr(Http::HdrType::HOST, request->peer_domain);
        } else {
            SBuf authority = request->url.authority();
            hdr_out->putStr(Http::HdrType::HOST, authority.c_str());
        }
    }

    /* append Authorization if known in URL, not in header and going direct */
    if (!hdr_out->has(Http::HdrType::AUTHORIZATION)) {
        if (flags.toOrigin && !request->url.userInfo().isEmpty()) {
            static char result[base64_encode_len(MAX_URL*2)]; // should be big enough for a single URI segment
            struct base64_encode_ctx ctx;
            base64_encode_init(&ctx);
            size_t blen = base64_encode_update(&ctx, result, request->url.userInfo().length(), reinterpret_cast<const uint8_t*>(request->url.userInfo().rawContent()));
            blen += base64_encode_final(&ctx, result+blen);
            result[blen] = '\0';
            if (blen)
                httpHeaderPutStrf(hdr_out, Http::HdrType::AUTHORIZATION, "Basic %.*s", (int)blen, result);
        }
    }

    /* Fixup (Proxy-)Authorization special cases. Plain relaying dealt with above */
    httpFixupAuthentication(request, hdr_in, hdr_out, peer, flags);

    /* append Cache-Control, add max-age if not there already */
    {
        HttpHdrCc *cc = hdr_in->getCc();

        if (!cc)
            cc = new HttpHdrCc();

        /* Add max-age only without no-cache */
        if (!cc->hasMaxAge() && !cc->hasNoCache()) {
            // XXX: performance regression. c_str() reallocates
            SBuf tmp(request->effectiveRequestUri());
            cc->maxAge(getMaxAge(entry ? entry->url() : tmp.c_str()));
        }

        /* Enforce sibling relations */
        if (flags.only_if_cached)
            cc->onlyIfCached(true);

        hdr_out->putCc(*cc);

        delete cc;
    }

    // Always send Connection because HTTP/1.0 servers need explicit
    // "keep-alive", HTTP/1.1 servers need explicit "close", Upgrade recipients
    // need bare "upgrade", and we do not always know the server expectations.
    if (!hdr_out->has(Http::HdrType::CONNECTION)) // forwardUpgrade() may add it
        hdr_out->putStr(Http::HdrType::CONNECTION, flags.keepalive ? "keep-alive" : "close");

    /* append Front-End-Https */
    if (flags.front_end_https) {
        if (flags.front_end_https == 1 || request->url.getScheme() == AnyP::PROTO_HTTPS)
            hdr_out->putStr(Http::HdrType::FRONT_END_HTTPS, "On");
    }

    if (flags.chunked_request) {
        // Do not just copy the original value so that if the client-side
        // starts decode other encodings, this code may remain valid.
        hdr_out->putStr(Http::HdrType::TRANSFER_ENCODING, "chunked");
    }

    /* Now mangle the headers. */
    httpHdrMangleList(hdr_out, request, al, ROR_REQUEST);

    strConnection.clean();
}

/// copies from-client Upgrade info into the given to-server header while
/// honoring configuration filters and following HTTP requirements
void
HttpStateData::forwardUpgrade(HttpHeader &hdrOut)
{
    if (!Config.http_upgrade_request_protocols)
        return; // forward nothing by default

    /* RFC 7230 section 6.7 paragraph 10:
     * A server MUST ignore an Upgrade header field that is received in
     * an HTTP/1.0 request.
     */
    if (request->http_ver == Http::ProtocolVersion(1,0))
        return;

    const auto &hdrIn = request->header;
    if (!hdrIn.has(Http::HdrType::UPGRADE))
        return;
    const auto upgradeIn = hdrIn.getList(Http::HdrType::UPGRADE);

    String upgradeOut;

    ACLFilledChecklist ch(nullptr, request.getRaw());
    ch.al = fwd->al;
    const char *pos = nullptr;
    const char *offeredStr = nullptr;
    int offeredStrLen = 0;
    while (strListGetItem(&upgradeIn, ',', &offeredStr, &offeredStrLen, &pos)) {
        const ProtocolView offeredProto(offeredStr, offeredStrLen);
        debugs(11, 5, "checks all rules applicable to " << offeredProto);
        Config.http_upgrade_request_protocols->forApplicable(offeredProto, [&ch, offeredStr, offeredStrLen, &upgradeOut] (const SBuf &cfgProto, const acl_access *guard) {
            debugs(11, 5, "checks " << cfgProto << " rule(s)");
            ch.changeAcl(guard);
            const auto &answer = ch.fastCheck();
            if (answer.implicit)
                return false; // keep looking for an explicit rule match
            if (answer.allowed())
                strListAdd(upgradeOut, offeredStr, offeredStrLen);
            // else drop the offer (explicitly denied cases and ACL errors)
            return true; // stop after an explicit rule match or an error
        });
    }

    if (upgradeOut.size()) {
        hdrOut.putStr(Http::HdrType::UPGRADE, upgradeOut.termedBuf());

        /* RFC 7230 section 6.7 paragraph 10:
         * When Upgrade is sent, the sender MUST also send a Connection header
         * field that contains an "upgrade" connection option, in
         * order to prevent Upgrade from being accidentally forwarded by
         * intermediaries that might not implement the listed protocols.
         *
         * NP: Squid does not truly implement the protocol(s) in this Upgrade.
         * For now we are treating an explicit blind tunnel as "implemented"
         * regardless of the security implications.
         */
        hdrOut.putStr(Http::HdrType::CONNECTION, "upgrade");

        // Connection:close and Connection:keepalive confuse some Upgrade
        // recipients, so we do not send those headers. Our Upgrade request
        // implicitly offers connection persistency per HTTP/1.1 defaults.
        // Update the keepalive flag to reflect that offer.
        // * If the server upgrades, then we would not be talking HTTP past the
        //   HTTP 101 control message, and HTTP persistence would be irrelevant.
        // * Otherwise, our request will contradict onoff.server_pconns=off or
        //   other no-keepalive conditions (if any). We compensate by copying
        //   the original no-keepalive decision now and honoring it later.
        flags.forceClose = !flags.keepalive;
        flags.keepalive = true; // should already be true in most cases
    }
}

/**
 * Decides whether a particular header may be cloned from the received Clients request
 * to our outgoing fetch request.
 */
void
copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, const String strConnection, const HttpRequest * request, HttpHeader * hdr_out, const int we_do_ranges, const Http::StateFlags &flags)
{
    debugs(11, 5, "httpBuildRequestHeader: " << e->name << ": " << e->value );

    switch (e->id) {

    /** \par RFC 2616 sect 13.5.1 - Hop-by-Hop headers which Squid should not pass on. */

    case Http::HdrType::PROXY_AUTHORIZATION:
        /** \par Proxy-Authorization:
         * Only pass on proxy authentication to peers for which
         * authentication forwarding is explicitly enabled
         */
        if (!flags.toOrigin && request->peer_login &&
                (strcmp(request->peer_login, "PASS") == 0 ||
                 strcmp(request->peer_login, "PROXYPASS") == 0 ||
                 strcmp(request->peer_login, "PASSTHRU") == 0)) {
            hdr_out->addEntry(e->clone());
        }
        break;

    /** \par RFC 2616 sect 13.5.1 - Hop-by-Hop headers which Squid does not pass on. */

    case Http::HdrType::CONNECTION:          /** \par Connection: */
    case Http::HdrType::TE:                  /** \par TE: */
    case Http::HdrType::KEEP_ALIVE:          /** \par Keep-Alive: */
    case Http::HdrType::PROXY_AUTHENTICATE:  /** \par Proxy-Authenticate: */
    case Http::HdrType::TRAILER:             /** \par Trailer: */
    case Http::HdrType::TRANSFER_ENCODING:   /** \par Transfer-Encoding: */
        break;

    /// \par Upgrade is hop-by-hop but forwardUpgrade() may send a filtered one
    case Http::HdrType::UPGRADE:
        break;

    /** \par OTHER headers I haven't bothered to track down yet. */

    case Http::HdrType::AUTHORIZATION:
        /** \par WWW-Authorization:
         * Pass on WWW authentication */

        if (!flags.toOriginPeer()) {
            hdr_out->addEntry(e->clone());
        } else {
            /** \note Assume that talking to a cache_peer originserver makes
             * us a reverse proxy and only forward authentication if enabled
             * (see also httpFixupAuthentication for special cases)
             */
            if (request->peer_login &&
                    (strcmp(request->peer_login, "PASS") == 0 ||
                     strcmp(request->peer_login, "PASSTHRU") == 0 ||
                     strcmp(request->peer_login, "PROXYPASS") == 0)) {
                hdr_out->addEntry(e->clone());
            }
        }

        break;

    case Http::HdrType::HOST:
        /** \par Host:
         * Normally Squid rewrites the Host: header.
         * However, there is one case when we don't: If the URL
         * went through our redirector and the admin configured
         * 'redir_rewrites_host' to be off.
         */
        if (request->peer_domain)
            hdr_out->putStr(Http::HdrType::HOST, request->peer_domain);
        else if (request->flags.redirected && !Config.onoff.redir_rewrites_host)
            hdr_out->addEntry(e->clone());
        else {
            SBuf authority = request->url.authority();
            hdr_out->putStr(Http::HdrType::HOST, authority.c_str());
        }

        break;

    case Http::HdrType::IF_MODIFIED_SINCE:
        /** \par If-Modified-Since:
         * append unless we added our own,
         * but only if cache_miss_revalidate is enabled, or
         *  the request is not cacheable, or
         *  the request contains authentication credentials.
         * \note at most one client's If-Modified-Since header can pass through
         */
        // XXX: need to check and cleanup the auth case so cacheable auth requests get cached.
        if (hdr_out->has(Http::HdrType::IF_MODIFIED_SINCE))
            break;
        else if (Config.onoff.cache_miss_revalidate || !request->flags.cachable || request->flags.auth)
            hdr_out->addEntry(e->clone());
        break;

    case Http::HdrType::IF_NONE_MATCH:
        /** \par If-None-Match:
         * append if the wildcard '*' special case value is present, or
         *   cache_miss_revalidate is disabled, or
         *   the request is not cacheable in this proxy, or
         *   the request contains authentication credentials.
         * \note this header lists a set of responses for the server to elide sending. Squid added values are extending that set.
         */
        // XXX: need to check and cleanup the auth case so cacheable auth requests get cached.
        if (hdr_out->hasListMember(Http::HdrType::IF_MATCH, "*", ',') || Config.onoff.cache_miss_revalidate || !request->flags.cachable || request->flags.auth)
            hdr_out->addEntry(e->clone());
        break;

    case Http::HdrType::MAX_FORWARDS:
        /** \par Max-Forwards:
         * pass only on TRACE or OPTIONS requests */
        if (request->method == Http::METHOD_TRACE || request->method == Http::METHOD_OPTIONS) {
            const int64_t hops = e->getInt64();

            if (hops > 0)
                hdr_out->putInt64(Http::HdrType::MAX_FORWARDS, hops - 1);
        }

        break;

    case Http::HdrType::VIA:
        /** \par Via:
         * If Via is disabled then forward any received header as-is.
         * Otherwise leave for explicit updated addition later. */

        if (!Config.onoff.via)
            hdr_out->addEntry(e->clone());

        break;

    case Http::HdrType::RANGE:

    case Http::HdrType::IF_RANGE:

    case Http::HdrType::REQUEST_RANGE:
        /** \par Range:, If-Range:, Request-Range:
         * Only pass if we accept ranges */
        if (!we_do_ranges)
            hdr_out->addEntry(e->clone());

        break;

    case Http::HdrType::PROXY_CONNECTION: // SHOULD ignore. But doing so breaks things.
        break;

    case Http::HdrType::CONTENT_LENGTH:
        // pass through unless we chunk; also, keeping this away from default
        // prevents request smuggling via Connection: Content-Length tricks
        if (!flags.chunked_request)
            hdr_out->addEntry(e->clone());
        break;

    case Http::HdrType::X_FORWARDED_FOR:

    case Http::HdrType::CACHE_CONTROL:
        /** \par X-Forwarded-For:, Cache-Control:
         * handled specially by Squid, so leave off for now.
         * append these after the loop if needed */
        break;

    case Http::HdrType::FRONT_END_HTTPS:
        /** \par Front-End-Https:
         * Pass thru only if peer is configured with front-end-https */
        if (!flags.front_end_https)
            hdr_out->addEntry(e->clone());

        break;

    default:
        /** \par default.
         * pass on all other header fields
         * which are NOT listed by the special Connection: header. */
        if (strConnection.size()>0 && strListIsMember(&strConnection, e->name, ',')) {
            debugs(11, 2, "'" << e->name << "' header cropped by Connection: definition");
            return;
        }

        hdr_out->addEntry(e->clone());
    }
}

bool
HttpStateData::decideIfWeDoRanges (HttpRequest * request)
{
    bool result = true;
    /* decide if we want to do Ranges ourselves
     * and fetch the whole object now)
     * We want to handle Ranges ourselves iff
     *    - we can actually parse client Range specs
     *    - the specs are expected to be simple enough (e.g. no out-of-order ranges)
     *    - reply will be cachable
     * (If the reply will be uncachable we have to throw it away after
     *  serving this request, so it is better to forward ranges to
     *  the server and fetch only the requested content)
     */

    int64_t roffLimit = request->getRangeOffsetLimit();

    if (nullptr == request->range || !request->flags.cachable
            || request->range->offsetLimitExceeded(roffLimit) || request->flags.connectionAuth)
        result = false;

    debugs(11, 8, "decideIfWeDoRanges: range specs: " <<
           request->range << ", cachable: " <<
           request->flags.cachable << "; we_do_ranges: " << result);

    return result;
}

/* build request prefix and append it to a given MemBuf;
 * return the length of the prefix */
mb_size_t
HttpStateData::buildRequestPrefix(MemBuf * mb)
{
    const int offset = mb->size;
    /* Uses a local httpver variable to print the HTTP label
     * since the HttpRequest may have an older version label.
     * XXX: This could create protocol bugs as the headers sent and
     * flow control should all be based on the HttpRequest version
     * not the one we are sending. Needs checking.
     */
    const AnyP::ProtocolVersion httpver = Http::ProtocolVersion();
    const SBuf url(flags.toOrigin ? request->url.path() : request->effectiveRequestUri());
    mb->appendf(SQUIDSBUFPH " " SQUIDSBUFPH " %s/%d.%d\r\n",
                SQUIDSBUFPRINT(request->method.image()),
                SQUIDSBUFPRINT(url),
                AnyP::ProtocolType_str[httpver.protocol],
                httpver.major,httpver.minor);
    /* build and pack headers */
    {
        HttpHeader hdr(hoRequest);
        forwardUpgrade(hdr); // before httpBuildRequestHeader() for CONNECTION
        const auto peer = cbdataReferenceValid(_peer) ? _peer : nullptr;
        httpBuildRequestHeader(request.getRaw(), entry, fwd->al, &hdr, peer, flags);

        if (request->flags.pinned && request->flags.connectionAuth)
            request->flags.authSent = true;
        else if (hdr.has(Http::HdrType::AUTHORIZATION))
            request->flags.authSent = true;

        // The late placement of this check supports reply_header_add mangling,
        // but also complicates optimizing upgradeHeaderOut-like lookups.
        if (hdr.has(Http::HdrType::UPGRADE)) {
            assert(!upgradeHeaderOut);
            upgradeHeaderOut = new String(hdr.getList(Http::HdrType::UPGRADE));
        }

        hdr.packInto(mb);
        hdr.clean();
    }
    /* append header terminator */
    mb->append(crlf, 2);
    return mb->size - offset;
}

/* This will be called when connect completes. Write request. */
bool
HttpStateData::sendRequest()
{
    MemBuf mb;

    debugs(11, 5, serverConnection << ", request " << request << ", this " << this << ".");

    if (!Comm::IsConnOpen(serverConnection)) {
        debugs(11,3, "cannot send request to closing " << serverConnection);
        assert(closeHandler != nullptr);
        return false;
    }

    typedef CommCbMemFunT<HttpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(11, 5,
                                      TimeoutDialer, this, HttpStateData::httpTimeout);
    commSetConnTimeout(serverConnection, Config.Timeout.lifetime, timeoutCall);
    maybeReadVirginBody();

    if (request->body_pipe != nullptr) {
        if (!startRequestBodyFlow()) // register to receive body data
            return false;
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(11,5,
                                    Dialer, this, HttpStateData::sentRequestBody);

        Must(!flags.chunked_request);
        // use chunked encoding if we do not know the length
        if (request->content_length < 0)
            flags.chunked_request = true;
    } else {
        assert(!requestBodySource);
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(11,5,
                                    Dialer, this,  HttpStateData::wroteLast);
    }

    /*
     * Is keep-alive okay for all request methods?
     */
    if (request->flags.mustKeepalive)
        flags.keepalive = true;
    else if (request->flags.pinned)
        flags.keepalive = request->persistent();
    else if (!Config.onoff.server_pconns)
        flags.keepalive = false;
    else if (flags.tunneling)
        // tunneled non pinned bumped requests must not keepalive
        flags.keepalive = !request->flags.sslBumped;
    else if (_peer == nullptr)
        flags.keepalive = true;
    else if (_peer->stats.n_keepalives_sent < 10)
        flags.keepalive = true;
    else if ((double) _peer->stats.n_keepalives_recv /
             (double) _peer->stats.n_keepalives_sent > 0.50)
        flags.keepalive = true;

    if (_peer && !flags.tunneling) {
        /*The old code here was
          if (neighborType(_peer, request->url) == PEER_SIBLING && ...
          which is equivalent to:
          if (neighborType(_peer, URL()) == PEER_SIBLING && ...
          or better:
          if (((_peer->type == PEER_MULTICAST && p->options.mcast_siblings) ||
                 _peer->type == PEER_SIBLINGS ) && _peer->options.allow_miss)
               flags.only_if_cached = 1;

           But I suppose it was a bug
         */
        if (neighborType(_peer, request->url) == PEER_SIBLING && !_peer->options.allow_miss)
            flags.only_if_cached = true;

        flags.front_end_https = _peer->front_end_https;
    }

    mb.init();
    buildRequestPrefix(&mb);

    debugs(11, 2, "HTTP Server " << serverConnection);
    debugs(11, 2, "HTTP Server REQUEST:\n---------\n" << mb.buf << "\n----------");

    Comm::Write(serverConnection, &mb, requestSender);
    return true;
}

bool
HttpStateData::getMoreRequestBody(MemBuf &buf)
{
    // parent's implementation can handle the no-encoding case
    if (!flags.chunked_request)
        return Client::getMoreRequestBody(buf);

    MemBuf raw;

    Must(requestBodySource != nullptr);
    if (!requestBodySource->getMoreData(raw))
        return false; // no request body bytes to chunk yet

    // optimization: pre-allocate buffer size that should be enough
    const mb_size_t rawDataSize = raw.contentSize();
    // we may need to send: hex-chunk-size CRLF raw-data CRLF last-chunk
    buf.init(16 + 2 + rawDataSize + 2 + 5, raw.max_capacity);

    buf.appendf("%x\r\n", static_cast<unsigned int>(rawDataSize));
    buf.append(raw.content(), rawDataSize);
    buf.append("\r\n", 2);

    Must(rawDataSize > 0); // we did not accidentally created last-chunk above

    // Do not send last-chunk unless we successfully received everything
    if (receivedWholeRequestBody) {
        Must(!flags.sentLastChunk);
        flags.sentLastChunk = true;
        buf.append("0\r\n\r\n", 5);
    }

    return true;
}

void
httpStart(FwdState *fwd)
{
    debugs(11, 3, fwd->request->method << ' ' << fwd->entry->url());
    AsyncJob::Start(new HttpStateData(fwd));
}

void
HttpStateData::start()
{
    if (!sendRequest()) {
        debugs(11, 3, "httpStart: aborted");
        mustStop("HttpStateData::start failed");
        return;
    }

    ++ statCounter.server.all.requests;
    ++ statCounter.server.http.requests;

    /*
     * We used to set the read timeout here, but not any more.
     * Now its set in httpSendComplete() after the full request,
     * including request body, has been written to the server.
     */
}

/// if broken posts are enabled for the request, try to fix and return true
bool
HttpStateData::finishingBrokenPost()
{
#if USE_HTTP_VIOLATIONS
    if (!Config.accessList.brokenPosts) {
        debugs(11, 5, "No brokenPosts list");
        return false;
    }

    ACLFilledChecklist ch(Config.accessList.brokenPosts, originalRequest().getRaw());
    ch.al = fwd->al;
    ch.syncAle(originalRequest().getRaw(), nullptr);
    if (!ch.fastCheck().allowed()) {
        debugs(11, 5, "didn't match brokenPosts");
        return false;
    }

    if (!Comm::IsConnOpen(serverConnection)) {
        debugs(11, 3, "ignoring broken POST for closed " << serverConnection);
        assert(closeHandler != nullptr);
        return true; // prevent caller from proceeding as if nothing happened
    }

    debugs(11, 3, "finishingBrokenPost: fixing broken POST");
    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    requestSender = JobCallback(11,5,
                                Dialer, this, HttpStateData::wroteLast);
    Comm::Write(serverConnection, "\r\n", 2, requestSender, nullptr);
    return true;
#else
    return false;
#endif /* USE_HTTP_VIOLATIONS */
}

/// if needed, write last-chunk to end the request body and return true
bool
HttpStateData::finishingChunkedRequest()
{
    if (flags.sentLastChunk) {
        debugs(11, 5, "already sent last-chunk");
        return false;
    }

    Must(receivedWholeRequestBody); // or we should not be sending last-chunk
    flags.sentLastChunk = true;

    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    requestSender = JobCallback(11,5, Dialer, this, HttpStateData::wroteLast);
    Comm::Write(serverConnection, "0\r\n\r\n", 5, requestSender, nullptr);
    return true;
}

void
HttpStateData::doneSendingRequestBody()
{
    Client::doneSendingRequestBody();
    debugs(11,5, serverConnection);

    // do we need to write something after the last body byte?
    if (flags.chunked_request && finishingChunkedRequest())
        return;
    if (!flags.chunked_request && finishingBrokenPost())
        return;

    sendComplete();
}

// more origin request body data is available
void
HttpStateData::handleMoreRequestBodyAvailable()
{
    if (eof || !Comm::IsConnOpen(serverConnection)) {
        // XXX: we should check this condition in other callbacks then!
        // TODO: Check whether this can actually happen: We should unsubscribe
        // as a body consumer when the above condition(s) are detected.
        debugs(11, DBG_IMPORTANT, "Transaction aborted while reading HTTP body");
        return;
    }

    assert(requestBodySource != nullptr);

    if (requestBodySource->buf().hasContent()) {
        // XXX: why does not this trigger a debug message on every request?

        if (flags.headers_parsed && !flags.abuse_detected) {
            flags.abuse_detected = true;
            debugs(11, DBG_IMPORTANT, "http handleMoreRequestBodyAvailable: Likely proxy abuse detected '" << request->client_addr << "' -> '" << entry->url() << "'" );

            if (virginReply()->sline.status() == Http::scInvalidHeader) {
                closeServer();
                mustStop("HttpStateData::handleMoreRequestBodyAvailable");
                return;
            }
        }
    }

    HttpStateData::handleMoreRequestBodyAvailable();
}

// premature end of the request body
void
HttpStateData::handleRequestBodyProducerAborted()
{
    Client::handleRequestBodyProducerAborted();
    if (entry->isEmpty()) {
        debugs(11, 3, "request body aborted: " << serverConnection);
        // We usually get here when ICAP REQMOD aborts during body processing.
        // We might also get here if client-side aborts, but then our response
        // should not matter because either client-side will provide its own or
        // there will be no response at all (e.g., if the the client has left).
        const auto err = new ErrorState(ERR_ICAP_FAILURE, Http::scInternalServerError, fwd->request, fwd->al);
        static const auto d = MakeNamedErrorDetail("SRV_REQMOD_REQ_BODY");
        err->detailError(d);
        fwd->fail(err);
    }

    abortTransaction("request body producer aborted");
}

// called when we wrote request headers(!) or a part of the body
void
HttpStateData::sentRequestBody(const CommIoCbParams &io)
{
    if (io.size > 0)
        statCounter.server.http.kbytes_out += io.size;

    Client::sentRequestBody(io);
}

void
HttpStateData::abortAll(const char *reason)
{
    debugs(11,5, "aborting transaction for " << reason <<
           "; " << serverConnection << ", this " << this);
    mustStop(reason);
}

HttpStateData::ReuseDecision::ReuseDecision(const StoreEntry *e, const Http::StatusCode code)
    : answer(HttpStateData::ReuseDecision::reuseNot), reason(nullptr), entry(e), statusCode(code) {}

HttpStateData::ReuseDecision::Answers
HttpStateData::ReuseDecision::make(const HttpStateData::ReuseDecision::Answers ans, const char *why)
{
    answer = ans;
    reason = why;
    return answer;
}

std::ostream &operator <<(std::ostream &os, const HttpStateData::ReuseDecision &d)
{
    static const char *ReuseMessages[] = {
        "do not cache and do not share", // reuseNot
        "cache positively and share", // cachePositively
        "cache negatively and share", // cacheNegatively
        "do not cache but share" // doNotCacheButShare
    };

    assert(d.answer >= HttpStateData::ReuseDecision::reuseNot &&
           d.answer <= HttpStateData::ReuseDecision::doNotCacheButShare);
    return os << ReuseMessages[d.answer] << " because " << d.reason <<
           "; HTTP status " << d.statusCode << " " << *(d.entry);
}


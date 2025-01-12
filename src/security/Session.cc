/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS session management */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/RunnersRegistry.h"
#include "CachePeer.h"
#include "debug/Stream.h"
#include "fd.h"
#include "fde.h"
#include "ipc/MemMap.h"
#include "security/Session.h"
#include "SquidConfig.h"
#include "ssl/bio.h"

#define SSL_SESSION_ID_SIZE 32
#define SSL_SESSION_MAX_SIZE 10*1024

#if USE_OPENSSL
static Ipc::MemMap *SessionCache = nullptr;
static const char *SessionCacheName = "tls_session_cache";
#endif

#ifdef ENABLE_SSL_THREAD

#include <pthread.h>

static const int READ = 0;
static const int WRITE = 1;

static int max_thread_counter = 0;
static int thread_counter = 0;

static void stop_signals(){
    // copy from squidaio_thread_loop
    sigset_t newSig;
    sigemptyset(&newSig);
    sigaddset(&newSig, SIGPIPE);
    sigaddset(&newSig, SIGCHLD);
    #if defined(_SQUID_LINUX_THREADS_)
    sigaddset(&newSig, SIGQUIT);
    sigaddset(&newSig, SIGTRAP);
    #else
    sigaddset(&newSig, SIGUSR1);
    sigaddset(&newSig, SIGUSR2);
    #endif
    sigaddset(&newSig, SIGHUP);
    sigaddset(&newSig, SIGTERM);
    sigaddset(&newSig, SIGINT);
    sigaddset(&newSig, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &newSig, nullptr);
}

static void *thread_reader_and_writer( void *args ){

    // stop receiving signals
    stop_signals();
    
    fde * const F_real = (fde *)args;
    
    fde * const F_R = &fd_table[F_real->ssl_th_info.piped_read_fd];
    fde * const F_W = &fd_table[F_real->ssl_th_info.piped_write_fd];

    const int real_fd = F_real->ssl_th_info.real_fd;

    const int piped_read_fd_at_thread = F_W->ssl_th_info.piped_read_fd_at_thread;
    const int piped_write_fd_at_thread = F_R->ssl_th_info.piped_write_fd_at_thread;
    
    SSL * const session = F_real->ssl.get();
    pthread_mutex_t * const ssl_mutex_p = &F_real->ssl_th_info.ssl_mutex;

    fcntl( piped_read_fd_at_thread, F_SETFL, fcntl(piped_read_fd_at_thread, F_GETFL) | O_NONBLOCK);
    fcntl( piped_write_fd_at_thread, F_SETFL, fcntl(piped_write_fd_at_thread, F_GETFL) | O_NONBLOCK);


    int destroying = 0;

    const int TH_BUF_SIZE = 16*1024;
    char buf_R[TH_BUF_SIZE];
    char buf_W[TH_BUF_SIZE];

    // named head & tail but not actually a ring buffer
    int read_buf_to_pipe_head = 0;
    int read_buf_to_pipe_tail = 0;

    int write_buf_to_ssl_head = 0;
    int write_buf_to_ssl_tail = 0;

    int error_ssl_read_side = 0;
    int error_ssl_write_side = 0;

    int kill_read_if_empty = 0;
    int kill_write_if_empty = 0;

    while(1){
        int did_something = 0;

        if (!error_ssl_read_side){
            if ( read_buf_to_pipe_head == read_buf_to_pipe_tail ){
                // read from ssl
                read_buf_to_pipe_head = 0;
                read_buf_to_pipe_tail = 0;

                int read_size = SSL_read(session, buf_R, TH_BUF_SIZE);

                if ( read_size > 0 ){
                    // read ok
                    
                    //int pending = SSL_pending(session);

                    read_buf_to_pipe_head += read_size;
                    did_something = 1;
                }
                else{
                    // read ng
                    int error = SSL_get_error(session, read_size);
                    
                    if ( kill_read_if_empty || !( error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ ) ){
                        kill_read_if_empty = 0;

                        error_ssl_read_side = 1;
                        did_something = 1;
                    }
                }
            }
            
            if ( read_buf_to_pipe_head != read_buf_to_pipe_tail ){
                // write to pipe

                int w_size = read_buf_to_pipe_head-read_buf_to_pipe_tail;
                int w = write(piped_write_fd_at_thread, buf_R+read_buf_to_pipe_tail, w_size);

                if ( w > 0 ){
                    // ok

                    read_buf_to_pipe_tail += w;
                    did_something = 1;
                }
                else if ( w == 0 ){
                    // ?

                    error_ssl_read_side = 1;
                    did_something = 1;                    
                }
                else{
                    // ng

                    if ( errno != EAGAIN ){
                        error_ssl_read_side = 1;
                        did_something = 1;
                    }
                }
            }
        }

        if (!error_ssl_write_side){
            if ( write_buf_to_ssl_head == write_buf_to_ssl_tail ){
                // read from pipe
                write_buf_to_ssl_head = 0;
                write_buf_to_ssl_tail = 0;

                int read_size = read(piped_read_fd_at_thread, buf_W, TH_BUF_SIZE);

                if ( read_size > 0 ){
                    // ok

                    write_buf_to_ssl_head += read_size;
                    did_something = 1;
                }
                else{
                    // ng or eof

                    if ( kill_write_if_empty || read_size == 0 || errno != EAGAIN ){
                        kill_write_if_empty = 0;

                        error_ssl_write_side = 1;
                        did_something = 1;
                    }
                }
            }

            if ( write_buf_to_ssl_head != write_buf_to_ssl_tail ){
                // write to ssl

				// max. 16KB for a cycle
                int w_size = min(16*1024, write_buf_to_ssl_head-write_buf_to_ssl_tail);
                int w = SSL_write(session, buf_W+write_buf_to_ssl_tail, w_size);
                if ( w > 0 ){
                    // ok
                    
                    write_buf_to_ssl_tail += w;
                    did_something = 1;
                }
                else{
                    // ng

                    int error = SSL_get_error(session, w);

                    if ( !( error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ ) ){
                        error_ssl_write_side = 1;
                        did_something = 1;
                    }
                }
            }
        }

        if ( error_ssl_read_side && error_ssl_write_side ){
            destroying = 1;
            break;
        }

        if ( error_ssl_read_side == 1 ){
            shutdown(piped_write_fd_at_thread, SHUT_RDWR);
            close(piped_write_fd_at_thread);

            error_ssl_read_side++;
            did_something = 1;
        }

        if ( error_ssl_write_side == 1 ){
            pthread_mutex_lock(ssl_mutex_p);
            if (!F_real->ssl_th_info.destroying){
            	// shutdown (SSL_shutdown) is done by parent if destroying is set
                shutdown(real_fd, SHUT_WR);
            }
            pthread_mutex_unlock(ssl_mutex_p);

            shutdown(piped_read_fd_at_thread, SHUT_RDWR);
            close(piped_read_fd_at_thread);

            error_ssl_write_side++;
            did_something = 1;
        }

        if (did_something){
        	// do the cycle again
            pthread_yield();
        }
        else {
        	// select route
        	
        	//debugs() is not thread safe
            //if ( error_ssl_read_side || error_ssl_write_side ){
            //    debugs(98, 3, "in select, errors: " << error_ssl_read_side << " " << error_ssl_write_side);
            //}
            
            if (destroying){
                break;
            }

            pthread_mutex_lock(ssl_mutex_p);
            if (F_real->ssl_th_info.destroying){
                destroying = 1;
            }
            pthread_mutex_unlock(ssl_mutex_p);

            if (destroying){
                // last cycle
                continue;
            }
            
        
            struct timeval tv;

            const int max_fd = max(real_fd, max(piped_read_fd_at_thread, piped_write_fd_at_thread));
    
            fd_set rfds;
            fd_set wfds;
            fd_set efds;

            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_ZERO(&efds);
            
            FD_SET(real_fd, &efds);
            
            if (!error_ssl_read_side){
                FD_SET(piped_write_fd_at_thread, &efds);

                if ( read_buf_to_pipe_head == read_buf_to_pipe_tail ){
                    FD_SET(real_fd, &rfds);
                }
                else{
                    FD_SET(piped_write_fd_at_thread, &wfds);
                }
            }

            if (!error_ssl_write_side){
                FD_SET(piped_read_fd_at_thread, &efds);
                
                if ( write_buf_to_ssl_head == write_buf_to_ssl_tail ){
                    FD_SET(piped_read_fd_at_thread, &rfds);
                }
                else{
                    FD_SET(real_fd, &wfds);
                }
            }

            tv.tv_sec = 5;
            tv.tv_usec = 500000;

            select(max_fd + 1, &rfds, &wfds, &efds, &tv);

            if (FD_ISSET(real_fd, &efds)){
                if (!error_ssl_read_side){
                	//close piped_write_fd_at_thread after flushing my buffer
                    kill_read_if_empty = 1;
                }
            }
            else{
                if (!error_ssl_read_side && FD_ISSET(piped_write_fd_at_thread, &efds)){
                    error_ssl_read_side = 1;
                }
                if (!error_ssl_write_side && FD_ISSET(piped_read_fd_at_thread, &efds)){
                	//shutdown real_fd after flushing my buffer
                    kill_write_if_empty = 1;
                }
            }
        }

    }


    if ( error_ssl_read_side <= 1 ){
        shutdown(piped_write_fd_at_thread, SHUT_RDWR);
        close(piped_write_fd_at_thread);
        error_ssl_read_side++;
    }

    if ( error_ssl_write_side <= 1 ){
        pthread_mutex_lock(ssl_mutex_p);
        if (!F_real->ssl_th_info.destroying){
        	// shutdown (SSL_shutdown) is done by parent if destroying is set
            shutdown(real_fd, SHUT_WR);
        }
        pthread_mutex_unlock(ssl_mutex_p);
        shutdown(piped_read_fd_at_thread, SHUT_RDWR);
        close(piped_read_fd_at_thread);
        error_ssl_write_side++;
    }

    return NULL;
    
}


void destroy_child(int fd){

    fde *F = &fd_table[fd];

    if ( ! F->ssl ){
        return;
    }

	if ( ! (F->ssl_th_info.ssl_threaded > 0) ){
		return;
	}
	
    int do_destroy = 0;
    pthread_mutex_t *mutex_p = &F->ssl_th_info.ssl_mutex;

	// set this flag by which the child thread starts finishing up
    pthread_mutex_lock(mutex_p);
    F->ssl_th_info.destroying++;
    pthread_mutex_unlock(mutex_p);
        
        
    debugs(98, 6, "write pipe close " << F->ssl_th_info.piped_write_fd);
    shutdown(F->ssl_th_info.piped_write_fd, SHUT_RDWR);
    close(F->ssl_th_info.piped_write_fd);
    
    debugs(98, 6, "read pipe close " << F->ssl_th_info.piped_read_fd);
    shutdown(F->ssl_th_info.piped_read_fd, SHUT_RDWR);
    close(F->ssl_th_info.piped_read_fd);
        
    debugs(98, 6, "destroy_child wait pthread_join for real_fd " << F->ssl_th_info.real_fd );
            
    pthread_join(F->ssl_th_info.th, NULL);
    
    debugs(98, 6, "pthread_join return ");

    debugs(98, 5, "destroy_child do_destroy " << do_destroy);

    thread_counter--;

    debugs(98, 3, "current Threads: " << thread_counter << "/" << Config.SSL.max_threads);

    if ( thread_counter == 0 ){
        max_thread_counter = 0;
        debugs(98, 2, "Zero SSL Threads: " << thread_counter);
    }

    pipe_free_wrap(fd);

    pthread_mutex_destroy(mutex_p);
    
    memset(&F->ssl_th_info, 0, sizeof(F->ssl_th_info));
}


static void create_ssl_read_and_write_thread( int fd ){
    int pipe_for_ssl_read[2];
    int pipe_for_ssl_write[2];

    if ( thread_counter >= Config.SSL.max_threads ){
        if (Config.SSL.max_threads > 0) debugs(98, 3, "max number of thread has reached, FD " << fd );
        return;
    }

    fde *F = &fd_table[fd];
    
    if (F->ssl_th_info.ssl_threaded)    // already created or failed
        return;

    int ret_pipe = pipe_open_wrap(fd, pipe_for_ssl_read, pipe_for_ssl_write);

    // error check
    if ( ret_pipe < 0 ){

        debugs(98, 1, "thread creation fail " );

        F->ssl_th_info.ssl_threaded = -1;

        return;
    }

    debugs(98, 3, "pipe created (read): FD " << fd << " pipes "
    	 << pipe_for_ssl_read[READ] << " " << pipe_for_ssl_read[WRITE]);
    	 
    debugs(98, 3, "pipe created (write): FD " << fd << " pipes "
    	 << pipe_for_ssl_write[READ] << " " << pipe_for_ssl_write[WRITE]);

    F->ssl_th_info.real_fd = fd;

    F->ssl_th_info.ssl_threaded = 1;


    pthread_t *th_p = &F->ssl_th_info.th;
    pthread_attr_t *attr_p = &F->ssl_th_info.attr;

    pthread_attr_init(attr_p);

    pthread_mutex_init(&F->ssl_th_info.ssl_mutex, NULL);

    int th_ret = pthread_create(th_p, attr_p, &thread_reader_and_writer, F);

    if (th_ret != 0){
        debugs(98, 1, "thread creation fail " );

        close(F->ssl_th_info.piped_read_fd);
        close(F->ssl_th_info.piped_write_fd_at_thread);
        close(F->ssl_th_info.piped_write_fd);
        close(F->ssl_th_info.piped_read_fd_at_thread);

        pipe_free_wrap(fd);

        pthread_mutex_destroy(&F->ssl_th_info.ssl_mutex);

        return;
    }

    if ( ++thread_counter > max_thread_counter ){
        max_thread_counter = thread_counter;
        debugs(98, 2, "max SSL Threads: " << thread_counter);
    }

    debugs(98, 3, "Threads for FD " << fd << "/" << FD_SETSIZE << " launched" );
    debugs(98, 3, "current Threads: " << thread_counter << "/" << Config.SSL.max_threads );

    return;
}
#endif

#if USE_OPENSSL || USE_GNUTLS
static int
tls_read_method(int _fd, char *buf, int len)
{
    int fd = _fd;

    auto session = fd_table[fd].ssl.get();
    debugs(83, 3, "started for session=" << (void*)session);

#if USE_OPENSSL
    int pending_fd = _fd;
    int threaded = 0;
    if (fd_table[_fd].ssl_th_info.ssl_threaded > 0){
        fd = fd_table[_fd].ssl_th_info.piped_read_fd;
        
        if (fd_table[fd].ssl_th_info.real_fd){
            pending_fd = fd_table[fd].ssl_th_info.real_fd;
            threaded = 1;
            debugs(98, 6, "now reading from pipe " << fd );
        }
        else{
        	// bug
            debugs(98, 1, "real_fd is not set!! " << fd );
        }
    }
    int i = 0;
    if (threaded){
        i = read(fd, buf, len);
    }
    else{
        i = SSL_read(session, buf, len);
    }
#elif USE_GNUTLS
    int i = gnutls_record_recv(session, buf, len);
#endif

    debugs(98, 4, "SSL_read " << fd << " " << len << " " << i << " bytes");

    if (i > 0) {
        debugs(83, 8, "TLS FD " << fd << " session=" << (void*)session << " " << i << " bytes");
        (void)VALGRIND_MAKE_MEM_DEFINED(buf, i);
    }

#if USE_OPENSSL
    if ( !threaded && i > 0 && SSL_pending(session) > 0) {
#elif USE_GNUTLS
    if (i > 0 && gnutls_record_check_pending(session) > 0) {
#endif
        debugs(83, 2, "TLS FD " << fd << " is pending");
        fd_table[pending_fd].flags.read_pending = true;
    } else
        fd_table[pending_fd].flags.read_pending = false;
	

#ifdef ENABLE_SSL_THREAD
    if (fd_table[_fd].ssl_th_info.ssl_threaded == 0 && i > 0){
        // read side thread creation

        fd_table[_fd].ssl_th_info.ssl_traffic_counter_read += i;
        
        // avoid threading a session with too little traffic
        if ( i >= min(16*1024, HTTP_REQBUF_SZ) ){
            
            // TODO: if (!ktls_is_enabled || ssl_traffic_counter_read exceeds some threshold such as 10MB)
            create_ssl_read_and_write_thread(_fd);
        }
    }
    else if (fd_table[_fd].ssl_th_info.ssl_traffic_counter_read == 0){
        fd_table[_fd].ssl_th_info.ssl_traffic_counter_read = 1; // need for POST case
    }
#endif

    return i;
}

static int
tls_write_method(int _fd, const char *buf, int len)
{
    int fd = _fd;

    auto session = fd_table[fd].ssl.get();
    debugs(83, 3, "started for session=" << (void*)session);

#if USE_OPENSSL
    int threaded = 0;
    if (fd_table[_fd].ssl_th_info.ssl_threaded > 0){
        fd = fd_table[_fd].ssl_th_info.piped_write_fd;

        if (fd_table[fd].ssl_th_info.real_fd){
            threaded = 1;
            debugs(98, 6, "now writing to pipe " << fd );
        }
        else{
        	// bug
            debugs(98, 1, "real_fd is not set!! " << fd  );
        }
    }
    else if (!SSL_is_init_finished(session)) {
        errno = ENOTCONN;
        return -1;
    }
#endif

#if USE_OPENSSL
    int i = 0;
    if (threaded){
        i = write(fd, buf, len);
        if ( i > fd_table[_fd].ssl_th_info.ssl_max_write_size ){
            debugs(98, 3, "ssl_max_write_size FD " << fd << ": "
            	 << fd_table[_fd].ssl_th_info.ssl_max_write_size << " -> " << i );
            fd_table[_fd].ssl_th_info.ssl_max_write_size = i;
        }
    }
    else{
        i = SSL_write(session, buf, len);
    }
#elif USE_GNUTLS
    int i = gnutls_record_send(session, buf, len);
#endif

    debugs(98, 4, "SSL_write " << fd << " " << len << " " << i << " bytes");


#ifdef ENABLE_SSL_THREAD
    if (!fd_table[_fd].ssl_th_info.ssl_threaded && i > 0){
        // write side thread creation

        fd_table[_fd].ssl_th_info.ssl_traffic_counter_write += i;

        // avoid threading a session with too little traffic
        if ( fd_table[_fd].ssl_th_info.ssl_traffic_counter_read > 0   // read must be started also
             && i >= min(16*1024, HTTP_REQBUF_SZ) ){

            // TODO: if (!ktls_is_enabled || ssl_traffic_counter_write exceeds some threshold such as 10MB)
            create_ssl_read_and_write_thread(_fd);
        }
    }
#endif


    if (i > 0) {
        debugs(83, 8, "TLS FD " << fd << " session=" << (void*)session << " " << i << " bytes");
    }
    return i;
}
#endif

#if USE_OPENSSL
Security::SessionPointer
Security::NewSessionObject(const Security::ContextPointer &ctx)
{
    Security::SessionPointer session(SSL_new(ctx.get()), [](SSL *p) {
        debugs(83, 5, "SSL_free session=" << (void*)p);
        SSL_free(p);
    });
    debugs(83, 5, "SSL_new session=" << (void*)session.get());
    return session;
}
#endif

static bool
CreateSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &conn, Security::PeerOptions &opts, Security::Io::Type type, const char *squidCtx)
{
    if (!Comm::IsConnOpen(conn)) {
        debugs(83, DBG_IMPORTANT, "Gone connection");
        return false;
    }

#if USE_OPENSSL || USE_GNUTLS

    const char *errAction = "with no TLS/SSL library";
    Security::LibErrorCode errCode = 0;
#if USE_OPENSSL
    Security::SessionPointer session(Security::NewSessionObject(ctx));
    if (!session) {
        errCode = ERR_get_error();
        errAction = "failed to allocate handle";
        debugs(83, DBG_IMPORTANT, "ERROR: TLS failure: " << errAction << ": " << Security::ErrorString(errCode));
    }
#elif USE_GNUTLS
    gnutls_session_t tmp;
    errCode = gnutls_init(&tmp, static_cast<unsigned int>(type) | GNUTLS_NONBLOCK);
    Security::SessionPointer session(tmp, [](gnutls_session_t p) {
        debugs(83, 5, "gnutls_deinit session=" << (void*)p);
        gnutls_deinit(p);
    });
    debugs(83, 5, "gnutls_init " << (type == Security::Io::BIO_TO_SERVER ? "client" : "server" )<< " session=" << (void*)session.get());
    if (errCode != GNUTLS_E_SUCCESS) {
        session.reset();
        errAction = "failed to initialize session";
        debugs(83, DBG_IMPORTANT, "ERROR: TLS failure: " << errAction << ": " << Security::ErrorString(errCode));
    }
#endif /* USE_GNUTLS */

    if (session) {
        const int fd = conn->fd;

#if USE_OPENSSL
        // without BIO, we would call SSL_set_fd(ssl.get(), fd) instead
        if (BIO *bio = Ssl::Bio::Create(fd, type)) {
            Ssl::Bio::Link(session.get(), bio); // cannot fail
#elif USE_GNUTLS
        errCode = gnutls_credentials_set(session.get(), GNUTLS_CRD_CERTIFICATE, ctx.get());
        if (errCode == GNUTLS_E_SUCCESS) {

            opts.updateSessionOptions(session);

            // NP: GnuTLS does not yet support the BIO operations
            //     this does the equivalent of SSL_set_fd() for now.
            gnutls_transport_set_int(session.get(), fd);
            gnutls_handshake_set_timeout(session.get(), GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif /* USE_GNUTLS */

            debugs(83, 5, "link FD " << fd << " to TLS session=" << (void*)session.get());

            memset(&fd_table[fd].ssl_th_info, 0, sizeof(fd_table[fd].ssl_th_info));

            fd_table[fd].ssl = session;
            fd_table[fd].useBufferedIo(&tls_read_method, &tls_write_method);
            fd_note(fd, squidCtx);
            return true;
        }

#if USE_OPENSSL
        errCode = ERR_get_error();
        errAction = "failed to initialize I/O";
        (void)opts;
#elif USE_GNUTLS
        errAction = "failed to assign credentials";
#endif
    }

    debugs(83, DBG_IMPORTANT, "ERROR: " << squidCtx << ' ' << errAction <<
           ": " << (errCode != 0 ? Security::ErrorString(errCode) : ""));
#else
    (void)ctx;
    (void)opts;
    (void)type;
    (void)squidCtx;
#endif /* USE_OPENSSL || USE_GNUTLS */
    return false;
}

bool
Security::CreateClientSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &c, const char *squidCtx)
{
    if (!c || !c->getPeer())
        return CreateSession(ctx, c, Security::ProxyOutgoingConfig, Security::Io::BIO_TO_SERVER, squidCtx);

    auto *peer = c->getPeer();
    return CreateSession(ctx, c, peer->secure, Security::Io::BIO_TO_SERVER, squidCtx);
}

bool
Security::CreateServerSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &c, Security::PeerOptions &o, const char *squidCtx)
{
    return CreateSession(ctx, c, o, Security::Io::BIO_TO_CLIENT, squidCtx);
}

void
Security::SessionSendGoodbye(const Security::SessionPointer &s)
{
    debugs(83, 5, "session=" << (void*)s.get());
    if (s) {
#if USE_OPENSSL
        SSL_shutdown(s.get());
#elif USE_GNUTLS
        gnutls_bye(s.get(), GNUTLS_SHUT_RDWR);
#endif
    }
}

bool
Security::SessionIsResumed(const Security::SessionPointer &s)
{
    bool result = false;
#if USE_OPENSSL
    result = SSL_session_reused(s.get()) == 1;
#elif USE_GNUTLS
    result = gnutls_session_is_resumed(s.get()) != 0;
#endif
    debugs(83, 7, "session=" << (void*)s.get() << ", query? answer: " << (result ? 'T' : 'F') );
    return result;
}

void
Security::MaybeGetSessionResumeData(const Security::SessionPointer &s, Security::SessionStatePointer &data)
{
    if (!SessionIsResumed(s)) {
#if USE_OPENSSL
        // nil is valid for SSL_get1_session(), it cannot fail.
        data.reset(SSL_get1_session(s.get()));
#elif USE_GNUTLS
        gnutls_datum_t *tmp = nullptr;
        const auto x = gnutls_session_get_data2(s.get(), tmp);
        if (x != GNUTLS_E_SUCCESS) {
            debugs(83, 3, "session=" << (void*)s.get() << " error: " << Security::ErrorString(x));
        }
        data.reset(tmp);
#endif
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get());
    } else {
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get() << ", do nothing.");
    }
}

void
Security::SetSessionResumeData(const Security::SessionPointer &s, const Security::SessionStatePointer &data)
{
    if (data) {
#if USE_OPENSSL
        if (!SSL_set_session(s.get(), data.get())) {
            const auto ssl_error = ERR_get_error();
            debugs(83, 3, "session=" << (void*)s.get() << " data=" << (void*)data.get() <<
                   " resume error: " << Security::ErrorString(ssl_error));
        }
#elif USE_GNUTLS
        const auto x = gnutls_session_set_data(s.get(), data->data, data->size);
        if (x != GNUTLS_E_SUCCESS) {
            debugs(83, 3, "session=" << (void*)s.get() << " data=" << (void*)data.get() <<
                   " resume error: " << Security::ErrorString(x));
        }
#else
        // critical because, how did it get here?
        debugs(83, DBG_CRITICAL, "no TLS library. session=" << (void*)s.get() << " data=" << (void*)data.get());
#endif
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get());
    } else {
        debugs(83, 5, "session=" << (void*)s.get() << " no resume data");
    }
}

static bool
isTlsServer()
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->secure.encryptTransport)
            return true;
        if (s->flags.tunnelSslBumping)
            return true;
    }

    return false;
}

#if USE_OPENSSL
static int
store_session_cb(SSL *, SSL_SESSION *session)
{
    if (!SessionCache)
        return 0;

    debugs(83, 5, "Request to store SSL_SESSION");

    SSL_SESSION_set_timeout(session, Config.SSL.session_ttl);

    unsigned int idlen;
    const unsigned char *id = SSL_SESSION_get_id(session, &idlen);
    // XXX: the other calls [to openForReading()] do not copy the sessionId to a char buffer, does this really have to?
    unsigned char key[MEMMAP_SLOT_KEY_SIZE];
    // Session ids are of size 32bytes. They should always fit to a
    // MemMap::Slot::key
    assert(idlen <= MEMMAP_SLOT_KEY_SIZE);
    memset(key, 0, sizeof(key));
    memcpy(key, id, idlen);
    int pos;
    if (auto slotW = SessionCache->openForWriting(static_cast<const cache_key*>(key), pos)) {
        int lenRequired = i2d_SSL_SESSION(session, nullptr);
        if (lenRequired <  MEMMAP_SLOT_DATA_SIZE) {
            unsigned char *p = static_cast<unsigned char *>(slotW->p);
            lenRequired = i2d_SSL_SESSION(session, &p);
            slotW->set(key, nullptr, lenRequired, squid_curtime + Config.SSL.session_ttl);
        }
        SessionCache->closeForWriting(pos);
        debugs(83, 5, "wrote an SSL_SESSION entry of size " << lenRequired << " at pos " << pos);
    }
    return 0;
}

static void
remove_session_cb(SSL_CTX *, SSL_SESSION *sessionID)
{
    if (!SessionCache)
        return;

    debugs(83, 5, "Request to remove corrupted or not valid SSL_SESSION");
    int pos;
    if (SessionCache->openForReading(reinterpret_cast<const cache_key*>(sessionID), pos)) {
        SessionCache->closeForReading(pos);
        // TODO:
        // What if we are not able to remove the session?
        // Maybe schedule a job to remove it later?
        // For now we just have an invalid entry in cache until will be expired
        // The OpenSSL library will reject it when we try to use it
        SessionCache->free(pos);
    }
}

static SSL_SESSION *
#if SQUID_USE_CONST_SSL_SESSION_CBID
get_session_cb(SSL *, const unsigned char *sessionID, int len, int *copy)
#else
get_session_cb(SSL *, unsigned char *sessionID, int len, int *copy)
#endif
{
    if (!SessionCache)
        return nullptr;

    const unsigned int *p = reinterpret_cast<const unsigned int *>(sessionID);
    debugs(83, 5, "Request to search for SSL_SESSION of len: " <<
           len << p[0] << ":" << p[1]);

    SSL_SESSION *session = nullptr;
    int pos;
    if (const auto slot = SessionCache->openForReading(static_cast<const cache_key*>(sessionID), pos)) {
        if (slot->expire > squid_curtime) {
            const unsigned char *ptr = slot->p;
            session = d2i_SSL_SESSION(nullptr, &ptr, slot->pSize);
            debugs(83, 5, "SSL_SESSION retrieved from cache at pos " << pos);
        } else
            debugs(83, 5, "SSL_SESSION in cache expired");
        SessionCache->closeForReading(pos);
    }

    if (!session)
        debugs(83, 5, "Failed to retrieve SSL_SESSION from cache");

    // With the parameter copy the callback can require the SSL engine
    // to increment the reference count of the SSL_SESSION object, Normally
    // the reference count is not incremented and therefore the session must
    // not be explicitly freed with SSL_SESSION_free(3).
    *copy = 0;
    return session;
}

void
Security::SetSessionCacheCallbacks(Security::ContextPointer &ctx)
{
    if (SessionCache) {
        SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);
        SSL_CTX_sess_set_new_cb(ctx.get(), store_session_cb);
        SSL_CTX_sess_set_remove_cb(ctx.get(), remove_session_cb);
        SSL_CTX_sess_set_get_cb(ctx.get(), get_session_cb);
    }
}
#endif /* USE_OPENSSL */

#if USE_OPENSSL
static void
initializeSessionCache()
{
    // Check if the MemMap keys and data are enough big to hold
    // session ids and session data
    assert(SSL_SESSION_ID_SIZE >= MEMMAP_SLOT_KEY_SIZE);
    assert(SSL_SESSION_MAX_SIZE >= MEMMAP_SLOT_DATA_SIZE);

    int configuredItems = ::Config.SSL.sessionCacheSize / sizeof(Ipc::MemMap::Slot);
    if (IamWorkerProcess() && configuredItems)
        SessionCache = new Ipc::MemMap(SessionCacheName);
    else {
        SessionCache = nullptr;
        return;
    }

    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->secure.staticContext)
            Security::SetSessionCacheCallbacks(s->secure.staticContext);
    }
}
#endif

/// initializes shared memory segments used by MemStore
class SharedSessionCacheRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    SharedSessionCacheRr(): owner(nullptr) {}
    void useConfig() override;
    ~SharedSessionCacheRr() override;

protected:
    void create() override;

private:
    Ipc::MemMap::Owner *owner;
};

DefineRunnerRegistrator(SharedSessionCacheRr);

void
SharedSessionCacheRr::useConfig()
{
#if USE_OPENSSL
    if (SessionCache || !isTlsServer()) // no need to configure SSL_SESSION* cache.
        return;

    Ipc::Mem::RegisteredRunner::useConfig();
    initializeSessionCache();
#endif
}

void
SharedSessionCacheRr::create()
{
    if (!isTlsServer()) // no need to configure SSL_SESSION* cache.
        return;

#if USE_OPENSSL
    if (int items = Config.SSL.sessionCacheSize / sizeof(Ipc::MemMap::Slot))
        owner = Ipc::MemMap::Init(SessionCacheName, items);
#endif
}

SharedSessionCacheRr::~SharedSessionCacheRr()
{
    // XXX: Enable after testing to reduce at-exit memory "leaks".
    // delete SessionCache;

    delete owner;
}


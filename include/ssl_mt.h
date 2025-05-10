
#ifndef SQUID_INCLUDE_SSL_MT_H
#define SQUID_INCLUDE_SSL_MT_H

#if defined(USE_OPENSSL) && (defined(USE_KQUEUE) || defined(USE_EPOLL))
    #include <pthread.h>

    #if _SQUID_FREEBSD_
    #include <pthread_np.h>
    #endif
    
	#define ENABLE_SSL_THREAD 1
    #define ENABLE_SSL_THREAD_ACCEPT 1
    #define ENABLE_SSL_THREAD_ACCEPT_REUSE 1
    
    #define ENABLE_SSL_THREAD_CONNECT 1 // more experimental
    
    extern pthread_mutex_t SSL_global_mutex;

	#if _SQUID_FREEBSD_
    	//#define SSL_THREAD_DEBUG    // only for debug
    #endif
        
#else
    #define ENABLE_SSL_THREAD 0
    #define ENABLE_SSL_THREAD_ACCEPT 0
    #define ENABLE_SSL_THREAD_CONNECT 0
    #define ENABLE_SSL_THREAD_ACCEPT_REUSE 0

#endif

#if ENABLE_SSL_THREAD
    #define SSL_MT_MUTEX_LOCK() \
    { \
        debugs(98,7,"try SSL_MT_MUTEX_LOCK"); \
        pthread_mutex_lock(&SSL_global_mutex); \
        if(0 == Debug::SSL_global_locking_count++) Debug::SSL_global_locking_thread = pthread_self(); \
        debugs(98,7,"SSL_MT_MUTEX_LOCK " << Debug::SSL_global_locking_count); \
    }

    #define SSL_MT_MUTEX_UNLOCK() \
    { \
        debugs(98,7,"SSL_MT_MUTEX_UNLOCK " << Debug::SSL_global_locking_count); \
        if(0 == --Debug::SSL_global_locking_count) Debug::SSL_global_locking_thread = 0; \
        pthread_mutex_unlock(&SSL_global_mutex); \
        sched_yield(); \
    }

    #define SSL_MT_MUTEX_IF_CHILD_LOCK() \
    { \
        if (is_ssl_child_thread()){ \
            child_debugs(98,7,"try SSL_MT_MUTEX_IF_CHILD_LOCK"); \
            pthread_mutex_lock(&SSL_global_mutex); \
            if(0 == Debug::SSL_global_locking_count++) Debug::SSL_global_locking_thread = pthread_self(); \
            child_debugs(98,7,"SSL_MT_MUTEX_IF_CHILD_LOCK " << Debug::SSL_global_locking_count); \
        } \
    }

    #define SSL_MT_MUTEX_IF_CHILD_UNLOCK() \
    { \
        if (is_ssl_child_thread()){ \
            child_debugs(98,7,"SSL_MT_MUTEX_IF_CHILD_UNLOCK " << Debug::SSL_global_locking_count); \
            if(0 == --Debug::SSL_global_locking_count) Debug::SSL_global_locking_thread = 0; \
            pthread_mutex_unlock(&SSL_global_mutex); \
            sched_yield(); \
        }\
    }

    inline bool is_ssl_child_thread(){
        #if _SQUID_FREEBSD_
        return ( pthread_main_np() == 0 );
        #elif _SQUID_LINUX_
        return ( getpid() != gettid() );
        #else
        return false;  // ssl multi-thread not supported
        #endif
    }
#else
    #define SSL_MT_MUTEX_LOCK()
    #define SSL_MT_MUTEX_UNLOCK()
#endif

#endif /* SQUID_INCLUDE_SSL_MT_H */



#ifndef SQUID_INCLUDE_SSL_MT_H
#define SQUID_INCLUDE_SSL_MT_H

#if defined(USE_OPENSSL) && (defined(USE_KQUEUE) || defined(USE_EPOLL))
    #include <pthread.h>

    #if _SQUID_FREEBSD_
    #include <pthread_np.h>
    #include <machine/atomic.h>
    extern pthread_cond_t SSL_global_cond;
    extern volatile u_int atomic_child_is_waiting;
    #endif
    
	#define ENABLE_SSL_THREAD 1
    #define ENABLE_SSL_THREAD_ACCEPT 1          // create a thread for SSL_accept()
    
    #define ENABLE_SSL_THREAD_CONNECT 1         // create a thread for SSL_connect()
    
    #define ENABLE_SSL_THREAD_ALWAYS_RW 1	// create a thread for SSL_read/write() before receiving/sending any
    
    extern pthread_mutex_t SSL_global_mutex;

    #define SSL_THREAD_DEFER_BUF_FLUSH  /* if defined, defer comm_close process and try to flush buffer 
                                           when data remain in buffer for ssl_write,
                                           otherwise force close such a session. */

    #define SSL_THREAD_DEBUG    // enable (thread-safe) debugs() output from child threads
        
#else
    #define ENABLE_SSL_THREAD 0
    #define ENABLE_SSL_THREAD_ACCEPT 0
    #define ENABLE_SSL_THREAD_CONNECT 0

#endif

#if ENABLE_SSL_THREAD
	// child threads should have higher priority
    #if _SQUID_FREEBSD_
        #define SSL_MT_WAIT_CHILD() \
            while(atomic_load_int(&atomic_child_is_waiting)){ \
                pthread_cond_wait(&SSL_global_cond, &SSL_global_mutex); \
            }

        #define SSL_MT_CHILD_IN() \
            atomic_fetchadd_int(&atomic_child_is_waiting, 1);

        #define SSL_MT_CHILD_OUT() \
            atomic_fetchadd_int(&atomic_child_is_waiting, -1); \
            pthread_cond_signal(&SSL_global_cond);

    #else
        #define SSL_MT_WAIT_CHILD() 
        #define SSL_MT_CHILD_IN() 
        #define SSL_MT_CHILD_OUT()
    #endif


    #define SSL_MT_MUTEX_LOCK() \
    { \
        debugs(98,8,"try SSL_MT_MUTEX_LOCK"); \
        pthread_mutex_lock(&SSL_global_mutex); \
        SSL_MT_WAIT_CHILD(); \
        if(0 == Debug::SSL_global_locking_count++) Debug::SSL_global_locking_thread = pthread_self(); \
        debugs(98,8,"SSL_MT_MUTEX_LOCK " << Debug::SSL_global_locking_count); \
    }

    #define SSL_MT_MUTEX_UNLOCK() \
    { \
        debugs(98,8,"SSL_MT_MUTEX_UNLOCK " << Debug::SSL_global_locking_count); \
        if(0 == --Debug::SSL_global_locking_count) Debug::SSL_global_locking_thread = 0; \
        pthread_mutex_unlock(&SSL_global_mutex); \
        sched_yield(); \
    }

    #define SSL_MT_MUTEX_IF_CHILD_LOCK() \
    { \
        if (is_ssl_child_thread()){ \
            child_debugs(98,7,"try SSL_MT_MUTEX_IF_CHILD_LOCK"); \
            SSL_MT_CHILD_IN(); \
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
            SSL_MT_CHILD_OUT(); \
            pthread_mutex_unlock(&SSL_global_mutex); \
            sched_yield(); \
        } \
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


#define SSL_MT_MUTEX_YIELD() \
{ \
    SSL_MT_MUTEX_UNLOCK() \
    SSL_MT_MUTEX_LOCK() \
}

#endif /* SQUID_INCLUDE_SSL_MT_H */


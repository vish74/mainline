#include <pthread.h>

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

int obexpushd_create_instance (void* (*cb)(void*), void *cbdata) {
	pthread_t t;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&t, &attr, cb, cbdata) != 0)
		return -errno;
	return 0;
}

static void obexpushd_listen_thread_cleanup (void* arg) {
	net_cleanup(arg);
}

static void* obexpushd_listen_thread (void* arg) {
	struct net_data* data = arg;

	pthread_cleanup_push(obexpushd_listen_thread_cleanup, arg);
	net_init(data, eventcb);
	if (!data->obex) {
		fprintf(stderr, "net_init() failed\n");
		pthread_exit(NULL);
	}
	do {
		if (OBEX_HandleInput(data->obex, 3600) < 0) {
			/* OpenOBEX sometimes return -1 anyway, must be a bug
			 * thus the break is commented -> go on anyway except
			 * when the transport is dead (e.g. one-shot).
			 */
			if (net_get_life_status(data) == LIFE_STATUS_DEAD)
				break;
		}
	} while (1);
	pthread_cleanup_pop(1);
	return NULL;
}

int obexpushd_start (struct net_data *data, unsigned int count) {
	unsigned int i;
	pthread_t *thread = calloc(count, sizeof(*thread));

	if (!thread)
		return -errno;

#if defined(USE_LIBGCRYPT)
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	(void)gcry_check_version(NULL);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

	/* initialize all enabled listeners */
	for (i = 0; i < count; ++i) {
		if (!data[i].handler)
			continue;
		if (pthread_create(&thread[i], NULL, obexpushd_listen_thread, &data[i]) != 0)
			perror("pthread_create()");
	}

	for (i = 0; i < count; ++i) {
		if (data[i].handler) {
			void* retval;
			pthread_join(thread[i], &retval);
		}
	}

	free(thread);
	pthread_exit(NULL);
}

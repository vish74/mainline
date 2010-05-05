#include <pthread.h>

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
			 * thus the break is commented -> go on anyway
			 */
			//break;
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
	pthread_exit(NULL);
}

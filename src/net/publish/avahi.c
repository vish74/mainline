#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/if.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/alternative.h>

#if defined(USE_THREADS)
#include <avahi-common/thread-watch.h>
#define obex_avahi_poll_quit(p) avahi_threaded_poll_stop(p);
#define obex_avahi_poll_free(p) avahi_threaded_poll_free(p);

#else
#include <avahi-common/simple-watch.h>
#define obex_avahi_poll_quit(p) avahi_simple_poll_quit(p);
#define obex_avahi_poll_free(p) avahi_simple_poll_free(p);
#endif

struct obex_avahi_data {
#if defined(USE_THREADS)
	AvahiThreadedPoll *p;
#else
	AvahiSimplePoll *p;
#endif
	AvahiClient *client;
	AvahiProtocol proto;
	uint16_t port;
	int intf;
	char *service_name;
};

static
int obex_avahi_service_register (AvahiEntryGroup *group, struct obex_avahi_data *oadata)
{
	int err = AVAHI_OK;

	if (avahi_entry_group_is_empty(group)) {
		do {
			err = avahi_entry_group_add_service(group, oadata->intf, oadata->proto, 0,
							    oadata->service_name, "_obex._tcp",
							    NULL, NULL, oadata->port,
							    "type=inbox", NULL);
			if (err == AVAHI_ERR_COLLISION)	{
				char* oldname = oadata->service_name;
				oadata->service_name = avahi_alternative_service_name(oldname);
				avahi_free(oldname);
				avahi_entry_group_reset(group);
			}
		} while (err == AVAHI_ERR_COLLISION);

		if (err == AVAHI_OK)
			err = avahi_entry_group_commit(group);
	}

	return err;
}

static
void obex_avahi_reset (AvahiEntryGroup *group)
{
	avahi_entry_group_reset(group);
}

static
void obex_avahi_group_cb (AvahiEntryGroup *group, AvahiEntryGroupState state, void *userdata)
{
	struct obex_avahi_data *oadata = userdata;

	switch (state) {
	case AVAHI_ENTRY_GROUP_UNCOMMITED:
		break;

	case AVAHI_ENTRY_GROUP_REGISTERING:
		break;

	case AVAHI_ENTRY_GROUP_ESTABLISHED:
		break;

	case AVAHI_ENTRY_GROUP_COLLISION:
		{
			char* oldname = oadata->service_name;
			oadata->service_name = avahi_alternative_service_name(oldname);
			avahi_free(oldname);
	        }
		obex_avahi_reset(group);
		obex_avahi_service_register(group, oadata);
		break;

	case AVAHI_ENTRY_GROUP_FAILURE:
		obex_avahi_poll_quit(oadata->p);
		break;

	}
}

static
void obex_avahi_client_cb (AvahiClient *client, AvahiClientState state, void *userdata)
{
	struct obex_avahi_data *oadata = userdata;
	AvahiEntryGroup *group = NULL;

	switch (state) {
	case AVAHI_CLIENT_S_RUNNING:
		if (!group) {
			group = avahi_entry_group_new(client, obex_avahi_group_cb, userdata);
			if (!group) {
				fprintf(stderr, "Creating avahi group failed: %s\n", avahi_strerror(avahi_client_errno(client)));
				return;
			}
		}			
		if (obex_avahi_service_register(group, oadata) != AVAHI_OK)
			obex_avahi_poll_quit(oadata->p);
		break;

	case AVAHI_CLIENT_S_REGISTERING:
	case AVAHI_CLIENT_S_COLLISION:
		obex_avahi_reset(group);
		break;

	case AVAHI_CLIENT_FAILURE:
		fprintf(stderr, "Avahi client failure: %s\n", avahi_strerror(avahi_client_errno(client)));
		obex_avahi_poll_quit(oadata->p);
		break;

	case AVAHI_CLIENT_CONNECTING:
		break;

	}
}

void* obex_avahi_setup (int af, uint16_t port, char *intf)
{
	struct obex_avahi_data *oadata = NULL;

#if defined(USE_THREADS)
	oadata = malloc(sizeof(*oadata));
	if (oadata) {
		oadata->p = avahi_threaded_poll_new();
		oadata->proto = avahi_af_to_proto(af);
		oadata->port = port;
		oadata->intf = (intf)? (int)if_nametoindex(intf): AVAHI_IF_UNSPEC;
		oadata->service_name = avahi_strdup("obexpushd");
		oadata->client = avahi_client_new(avahi_threaded_poll_get(oadata->p), AVAHI_CLIENT_NO_FAIL,
						  &obex_avahi_client_cb, oadata, NULL);
		avahi_threaded_poll_start(oadata->p);
	}
#else
	/* not yet implemented */
#endif
	return oadata;
}

void obex_avahi_cleanup (void *ptr)
{
	struct obex_avahi_data *oadata = ptr;

	if (!oadata)
		return;

	if (oadata->p) {
		obex_avahi_poll_quit(oadata->p);
		obex_avahi_poll_free(oadata->p);
		oadata->p = NULL;
	}
	if (oadata->service_name) {
		avahi_free(oadata->service_name);
	}
	free(oadata);
}

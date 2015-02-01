CC ?= gcc

TARGETS = utc_ApplicationFW_package_manager_compare_app_cert_info \
	utc_ApplicationFW_package_manager_compare_package_cert_info \
	utc_ApplicationFW_package_manager_create \
	utc_ApplicationFW_package_manager_destroy \
	utc_ApplicationFW_package_manager_foreach_package_info \
	utc_ApplicationFW_package_manager_get_package_id_by_app_id \
	utc_ApplicationFW_package_manager_get_permission_type \
	utc_ApplicationFW_package_manager_is_preload_package_by_app_id \
	utc_ApplicationFW_package_manager_request_create \
	utc_ApplicationFW_package_manager_request_destroy \
	utc_ApplicationFW_package_manager_request_install \
	utc_ApplicationFW_package_manager_request_set_event_cb \
	utc_ApplicationFW_package_manager_request_set_mode \
	utc_ApplicationFW_package_manager_request_set_type \
	utc_ApplicationFW_package_manager_request_move \
	utc_ApplicationFW_package_manager_request_uninstall \
	utc_ApplicationFW_package_manager_request_unset_event_cb \
	utc_ApplicationFW_package_manager_set_event_cb \
	utc_ApplicationFW_package_manager_unset_event_cb \
	utc_ApplicationFW_package_info_create \
	utc_ApplicationFW_package_info_destroy \
	utc_ApplicationFW_package_info_clone \
	utc_ApplicationFW_package_info_foreach_app_from_package \
	utc_ApplicationFW_package_info_foreach_cert_info \
	utc_ApplicationFW_package_info_get_icon \
	utc_ApplicationFW_package_info_get_installed_storage\
	utc_ApplicationFW_package_info_get_label\
	utc_ApplicationFW_package_info_get_package\
	utc_ApplicationFW_package_info_get_type\
	utc_ApplicationFW_package_info_get_version\
	utc_ApplicationFW_package_info_get_root_path\
	utc_ApplicationFW_package_info_is_accessible\
	utc_ApplicationFW_package_info_is_equal\
	utc_ApplicationFW_package_info_is_preload_package\
	utc_ApplicationFW_package_info_is_removable_package\
	utc_ApplicationFW_package_info_is_system_package

PKGS = glib-2.0 dlog capi-appfw-package-manager

LDFLAGS = `pkg-config --libs $(PKGS)`
LDFLAGS += $(TET_ROOT)/lib/tet3/tcm_s.o
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -ltcm_s
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -lapi_s
LDFLAGS += -L/usr/lib -lpthread

CFLAGS = -I. `pkg-config --cflags $(PKGS)`
CFLAGS += -I$(TET_ROOT)/inc/tet3
CFLAGS += -Wall

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGETS)

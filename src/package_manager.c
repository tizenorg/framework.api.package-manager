/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <dlog.h>

#include <package-manager.h>
#include <package_manager.h>
#include <pkgmgr-info.h>

#include <package_manager_internal.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_PACKAGE_MANAGER"

#define _LOGE(fmt, arg...) LOGE(fmt,##arg)
#define _LOGD(fmt, arg...) LOGD(fmt, ##arg)

static GHashTable *__cb_table = NULL;

typedef struct _event_info {
	int req_id;
	package_manager_event_type_e event_type;
	package_manager_event_state_e event_state;
	struct _event_info *next;
} event_info;

struct package_manager_s {
	int handle_id;
	client_type ctype;
	pkgmgr_client *pc;
	pkgmgr_mode mode;
	event_info *head;
	package_manager_event_cb event_cb;
	void *user_data;
};

struct package_manager_request_s {
	int handle_id;
	client_type ctype;
	pkgmgr_client *pc;
	const char *pkg_type;
	const char *pkg_path;
	const char *pkg_name;
	pkgmgr_mode mode;
	event_info *head;
	package_manager_request_event_cb event_cb;
	void *user_data;
};

struct package_manager_filter_s {
	pkgmgrinfo_pkginfo_filter_h pkgmgrinfo_pkginfo_filter;
};

static int package_manager_request_new_id()
{
	static int request_handle_id = 0;
	return request_handle_id++;
}

static int package_manager_new_id()
{
	static int manager_handle_id = 0;
	return manager_handle_id++;
}

static const char *package_manager_error_to_string(package_manager_error_e
						   error)
{
	switch (error) {
	case PACKAGE_MANAGER_ERROR_NONE:
		return "NONE";
	case PACKAGE_MANAGER_ERROR_INVALID_PARAMETER:
		return "INVALID_PARAMETER";
	case PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY:
		return "OUT_OF_MEMORY";
	case PACKAGE_MANAGER_ERROR_IO_ERROR:
		return "IO_ERROR";
	case PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE:
		return "NO_SUCH_PACKAGE";
	case PACKAGE_MANAGER_ERROR_PERMISSION_DENIED:
		return "PERMISSION_DENIED";
	case PACKAGE_MANAGER_ERROR_SYSTEM_ERROR:
		return "SEVERE_SYSTEM_ERROR";
	default:
		return "UNKNOWN";
	}
}

int package_manager_error(package_manager_error_e error,
				 const char *function, const char *description)
{
	if (description) {
		_LOGE("[%s] %s(0x%08x) : %s", function,
		     package_manager_error_to_string(error), error,
		     description);
	} else {
		_LOGE("[%s] %s(0x%08x)", function,
		     package_manager_error_to_string(error), error);
	}

	return error;
}

int package_manager_request_create(package_manager_request_h * request)
{
	struct package_manager_request_s *package_manager_request;

	if (request == NULL) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	package_manager_request =
	    calloc(1, sizeof(struct package_manager_request_s));
	if (package_manager_request == NULL) {
		return
		    package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY,
					  __FUNCTION__,
					  "failed to create a package_manager handle");
	}

	package_manager_request->ctype = PC_REQUEST;
	package_manager_request->pc = pkgmgr_client_new(PC_REQUEST);
	if (package_manager_request->pc == NULL) {
		free(package_manager_request);
		return
		    package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY,
					  __FUNCTION__,
					  "failed to create a package_manager client");
	}

	package_manager_request->handle_id = package_manager_request_new_id();

	*request = package_manager_request;

	return PACKAGE_MANAGER_ERROR_NONE;
}

static int package_manager_client_validate_handle(package_manager_request_h
						 request)
{
	if (request == NULL || request->pc == NULL) {
		return PACKAGE_MANAGER_ERROR_INVALID_PARAMETER;
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_client_destroy(package_manager_request_h request)
{
	if (package_manager_client_validate_handle(request)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	pkgmgr_client_free(request->pc);
	request->pc = NULL;
	free(request);

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_destroy(package_manager_request_h request)
{
	if (package_manager_client_validate_handle(request)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	pkgmgr_client_free(request->pc);
	request->pc = NULL;
	free(request);

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_set_event_cb(package_manager_request_h request,
					 package_manager_request_event_cb
					 callback, void *user_data)
{
	int retval;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if (package_manager_client_validate_handle(request)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	request->event_cb = callback;
	request->user_data = user_data;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_unset_event_cb(package_manager_request_h request)
{
	// TODO: Please implement this function.
	if (package_manager_client_validate_handle(request)) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}


int package_manager_request_set_type(package_manager_request_h request,
				     const char *pkg_type)
{
	if (package_manager_client_validate_handle(request)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	request->pkg_type = pkg_type;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_set_mode(package_manager_request_h request,
				     package_manager_request_mode_e mode)
{
	if (package_manager_client_validate_handle(request)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	if (mode == PACKAGE_MANAGER_REQUEST_MODE_QUIET)
		request->mode = PM_QUIET;
	else
		request->mode = PM_DEFAULT;

	return PACKAGE_MANAGER_ERROR_NONE;
}

static int package_manager_get_event_type(const char *key,
					  package_manager_event_type_e *
					  event_type)
{
	if (key == NULL)
		return PACKAGE_MANAGER_ERROR_INVALID_PARAMETER;

	if (strcasecmp(key, "install") == 0)
		*event_type = PACKAGE_MANAGER_EVENT_TYPE_INSTALL;
	else if (strcasecmp(key, "uninstall") == 0)
		*event_type = PACKAGE_MANAGER_EVENT_TYPE_UNINSTALL;
	else if (strcasecmp(key, "update") == 0)
		*event_type = PACKAGE_MANAGER_EVENT_TYPE_UPDATE;
	else
		return PACKAGE_MANAGER_ERROR_INVALID_PARAMETER;

	return PACKAGE_MANAGER_ERROR_NONE;
}

static int __add_event_info(event_info ** head, int req_id,
			    package_manager_event_type_e event_type,
			    package_manager_event_state_e event_state)
{
	event_info *evt_info;
	event_info *current;
	event_info *prev;

	evt_info = (event_info *) calloc(1, sizeof(event_info));
	if (evt_info == NULL) {
		_LOGD("calloc failed");
		return -1;
	}
	evt_info->req_id = req_id;
	evt_info->event_type = event_type;
	evt_info->next = NULL;

	if (*head == NULL)
		*head = evt_info;
	else {
		current = prev = *head;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = evt_info;
	}

	return 0;
}

static int __find_event_info(event_info ** head, int req_id,
			     package_manager_event_type_e * event_type,
			     package_manager_event_state_e * event_state)
{
	event_info *tmp;

	tmp = *head;

	if (tmp == NULL) {
		_LOGE("tmp is NULL");
		return -1;
	}

	_LOGD("tmp->req_id %d, event_type %d", tmp->req_id, event_type);

	while (tmp) {
		if (tmp->req_id == req_id) {
			*event_type = tmp->event_type;
			return 0;
		}
		tmp = tmp->next;
	}
	return -1;
}

static int __update_event_info(event_info ** head, int req_id,
			       package_manager_event_type_e event_type,
			       package_manager_event_state_e event_state)
{
	package_manager_event_type_e evt_type;
	package_manager_event_state_e evt_state;
	event_info *tmp;

	if (__find_event_info(head, req_id, &evt_type, &evt_state) != 0)
		__add_event_info(head, req_id, event_type, event_state);
	else {
		tmp = *head;

		if (tmp == NULL) {
			_LOGE("tmp is NULL");
			return -1;
		}

		while (tmp) {
			if (tmp->req_id == req_id) {
				tmp->event_type = event_type;
				return 0;
			}
			tmp = tmp->next;
		}
	}

	return -1;
}

/*
static int __remove_event_info(event_info **head request, int req_id)
{
	event_info *current;
	event_info *tmp;

	if (* == NULL)
		return -1;

	current = *head;
	while (current) {
		if (current->next) {
			if (current->next->req_id == req_id) {
				tmp = current->next;
				current->next = current->next->next;
				free(tmp);
				return 0;
			}
		}
		tmp = tmp->next;
	}

	return -1;
}
*/

static int request_event_handler(int req_id, const char *pkg_type,
				 const char *pkg_name, const char *key,
				 const char *val, const void *pmsg, void *data)
{
	int ret = -1;
	package_manager_event_type_e event_type = -1;
	package_manager_event_state_e event_state = -1;

	_LOGD("request_event_handler is called");

	package_manager_request_h request = data;

	if (strcasecmp(key, "start") == 0) {
		ret = package_manager_get_event_type(val, &event_type);
		if (ret != PACKAGE_MANAGER_ERROR_NONE)
			return PACKAGE_MANAGER_ERROR_INVALID_PARAMETER;

		__add_event_info(&(request->head), req_id, event_type,
				 PACKAGE_MANAGER_EVENT_STATE_STARTED);

		if (request->event_cb)
			request->event_cb(req_id, pkg_type, pkg_name,
					  event_type,
					  PACKAGE_MANAGER_EVENT_STATE_STARTED,
					  0, PACKAGE_MANAGER_ERROR_NONE, request->user_data);

	} else if (strcasecmp(key, "install_percent") == 0
		   || strcasecmp(key, "progress_percent") == 0) {
		if (__find_event_info
		    (&(request->head), req_id, &event_type,
		     &event_state) == 0) {
			__update_event_info(&(request->head), req_id,
					    event_type,
					    PACKAGE_MANAGER_EVENT_STATE_PROCESSING);
			if (request->event_cb)
				request->event_cb(req_id, pkg_type, pkg_name,
						  event_type,
						  PACKAGE_MANAGER_EVENT_STATE_PROCESSING,
						  atoi(val),
						  PACKAGE_MANAGER_ERROR_NONE,
						  request->user_data);
		}

	} else if (strcasecmp(key, "error") == 0) {
		if (strcasecmp(key, "0") != 0) {
			if (__find_event_info
			    (&(request->head), req_id, &event_type,
			     &event_state) == 0) {
				__update_event_info(&(request->head), req_id,
						    event_type,
						    PACKAGE_MANAGER_EVENT_STATE_FAILED);
			}

			if (request->event_cb)
				request->event_cb(req_id, pkg_type,
						  pkg_name, event_type,
						  PACKAGE_MANAGER_EVENT_STATE_FAILED,
						  0,
						  PACKAGE_MANAGER_ERROR_NONE,
						  request->user_data);

		}
	} else if (strcasecmp(key, "end") == 0) {
		if (__find_event_info
		    (&(request->head), req_id, &event_type,
		     &event_state) == 0) {
			if (event_state != PACKAGE_MANAGER_EVENT_STATE_FAILED) {
				if (request->event_cb)
					request->event_cb(req_id, pkg_type,
							  pkg_name, event_type,
							  PACKAGE_MANAGER_EVENT_STATE_COMPLETED,
							  100,
							  PACKAGE_MANAGER_ERROR_NONE,
							  request->user_data);
			}
		} else {
			if (strcasecmp(key, "ok") != 0)
				if (request->event_cb)
					request->event_cb(req_id, pkg_type,
							  pkg_name, event_type,
							  PACKAGE_MANAGER_EVENT_STATE_FAILED,
							  0,
							  PACKAGE_MANAGER_ERROR_NONE,
							  request->user_data);
		}
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_install(package_manager_request_h request,
				    const char *path, int *id)
{
	if (package_manager_client_validate_handle(request)) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}
	if (path == NULL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	int request_id = 0;
	request->pkg_path = path;
	request_id = pkgmgr_client_install(request->pc, request->pkg_type, NULL,
					   request->pkg_path, NULL,
					   request->mode, request_event_handler,
					   request);

	if (request_id == PKGMGR_R_EINVAL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_ENOPKG) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_ENOMEM) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_EIO) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_EPRIV) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_ESYSTEM || request_id == PKGMGR_R_ECOMM || request_id == PKGMGR_R_ERROR) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}

	*id = request_id;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_uninstall(package_manager_request_h request,
				      const char *name, int *id)
{
	if (package_manager_client_validate_handle(request)) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}
	if (name == NULL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	int request_id = 0;
	request->pkg_name = name;
	request_id = pkgmgr_client_uninstall(request->pc, request->pkg_type,
					     request->pkg_name, request->mode,
					     request_event_handler, request);

	if (request_id == PKGMGR_R_EINVAL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_ENOPKG) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_ENOMEM) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_EIO) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_EPRIV) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);
	} else if (request_id == PKGMGR_R_ESYSTEM || request_id == PKGMGR_R_ECOMM || request_id == PKGMGR_R_ERROR) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}

	*id = request_id;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_request_move(package_manager_request_h request,
				    const char *name, package_manager_move_type_e move_type)
{
	if (package_manager_client_validate_handle(request)) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}
	if (name == NULL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	int ret = 0;
	request->pkg_name = name;
	ret = pkgmgr_client_move(request->pc, request->pkg_name, move_type, request_event_handler, request);

	if (ret == PKGMGR_R_EINVAL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	} else if (ret == PKGMGR_R_ENOPKG) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	} else if (ret == PKGMGR_R_ENOMEM) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	} else if (ret == PKGMGR_R_EIO) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	} else if (ret == PKGMGR_R_EPRIV) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);
	} else if (ret == PKGMGR_R_ESYSTEM || ret == PKGMGR_R_ECOMM || ret == PKGMGR_R_ERROR) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}
int package_manager_create(package_manager_h * manager)
{
	int ret;

	ret = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (ret != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(ret, __FUNCTION__,
			 "failed to allow privilege");
	}

	struct package_manager_s *package_manager = NULL;

	if (manager == NULL) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	package_manager = calloc(1, sizeof(struct package_manager_s));
	if (package_manager == NULL) {
		return
		    package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY,
					  __FUNCTION__,
					  "failed to create a package_manager handle");
	}

	package_manager->ctype = PC_LISTENING;
	package_manager->pc = pkgmgr_client_new(PC_LISTENING);
	if (package_manager->pc == NULL) {
		free(package_manager);
		return
		    package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY,
					  __FUNCTION__,
					  "failed to create a package_manager client");
	}

	package_manager->handle_id = package_manager_new_id();

	*manager = package_manager;

	return PACKAGE_MANAGER_ERROR_NONE;
}

static int package_manager_validate_handle(package_manager_h manager)
{
	if (manager == NULL || manager->pc == NULL) {
		return PACKAGE_MANAGER_ERROR_INVALID_PARAMETER;
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_destroy(package_manager_h manager)
{
	if (package_manager_validate_handle(manager)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	pkgmgr_client_free(manager->pc);
	manager->pc = NULL;
	free(manager);

	return PACKAGE_MANAGER_ERROR_NONE;
}

static int __add_event(event_info ** head, int req_id,
			    package_manager_event_type_e event_type,
			    package_manager_event_state_e event_state)
{
	event_info *evt_info;

	evt_info = (event_info *) calloc(1, sizeof(event_info));
	if (evt_info == NULL) {
		_LOGD("calloc failed");
		return -1;
	}
	evt_info->req_id = req_id;
	evt_info->event_type = event_type;
	evt_info->next = NULL;

	*head = evt_info;

	return 0;
}

static int __find_event(event_info ** head, int req_id,
			     package_manager_event_type_e * event_type,
			     package_manager_event_state_e * event_state)
{
	event_info *tmp;

	tmp = *head;

	if (tmp == NULL) {
		_LOGE("tmp is NULL");
		return -1;
	}

	*event_type = tmp->event_type;
	return 0;
}

static int __update_event(event_info ** head, int req_id,
			       package_manager_event_type_e event_type,
			       package_manager_event_state_e event_state)
{
	package_manager_event_type_e evt_type;
	package_manager_event_state_e evt_state;
	event_info *tmp;

	if (__find_event_info(head, req_id, &evt_type, &evt_state) != 0)
		__add_event_info(head, req_id, event_type, event_state);
	else {
		tmp = *head;

		if (tmp == NULL) {
			_LOGE("tmp is NULL");
			return -1;
		}

		tmp->event_type = event_type;
		return 0;
	}

	return -1;
}

static int global_event_handler(int req_id, const char *pkg_type,
				const char *pkg_name, const char *key,
				const char *val, const void *pmsg, void *data)
{
	int ret = -1;
	package_manager_event_type_e event_type = -1;
	package_manager_event_state_e event_state = -1;

	_LOGD("global_event_handler is called");

	package_manager_h manager = data;

	if (strcasecmp(key, "start") == 0) {
		ret = package_manager_get_event_type(val, &event_type);
		if (ret != PACKAGE_MANAGER_ERROR_NONE)
			return PACKAGE_MANAGER_ERROR_INVALID_PARAMETER;

		__add_event(&(manager->head), req_id, event_type,
				 PACKAGE_MANAGER_EVENT_STATE_STARTED);

		if (manager->event_cb)
			manager->event_cb(pkg_type, pkg_name,
					  event_type,
					  PACKAGE_MANAGER_EVENT_STATE_STARTED,
					  0, PACKAGE_MANAGER_ERROR_NONE, manager->user_data);

	} else if (strcasecmp(key, "install_percent") == 0
		   || strcasecmp(key, "progress_percent") == 0) {
		if (__find_event
		    (&(manager->head), req_id, &event_type,
		     &event_state) == 0) {
			__update_event(&(manager->head), req_id,
					    event_type,
					    PACKAGE_MANAGER_EVENT_STATE_PROCESSING);
			if (manager->event_cb)
				manager->event_cb(pkg_type, pkg_name,
						  event_type,
						  PACKAGE_MANAGER_EVENT_STATE_PROCESSING,
						  atoi(val),
						  PACKAGE_MANAGER_ERROR_NONE,
						  manager->user_data);
		}

	} else if (strcasecmp(key, "error") == 0) {
		if (strcasecmp(key, "0") != 0) {
			if (__find_event
			    (&(manager->head), req_id, &event_type,
			     &event_state) == 0) {
				__update_event(&(manager->head), req_id,
						    event_type,
						    PACKAGE_MANAGER_EVENT_STATE_FAILED);
			}

			if (manager->event_cb)
				manager->event_cb(pkg_type,
						  pkg_name, event_type,
						  PACKAGE_MANAGER_EVENT_STATE_FAILED,
						  0,
						  PACKAGE_MANAGER_ERROR_NONE,
						  manager->user_data);

		}
	} else if (strcasecmp(key, "end") == 0) {
		if (__find_event
		    (&(manager->head), req_id, &event_type,
		     &event_state) == 0) {
			if (event_state != PACKAGE_MANAGER_EVENT_STATE_FAILED) {
				if (manager->event_cb)
					manager->event_cb(pkg_type,
							  pkg_name, event_type,
							  PACKAGE_MANAGER_EVENT_STATE_COMPLETED,
							  100,
							  PACKAGE_MANAGER_ERROR_NONE,
							  manager->user_data);
			}
		} else {
			if (strcasecmp(key, "ok") != 0)
				if (manager->event_cb)
					manager->event_cb(pkg_type,
							  pkg_name, event_type,
							  PACKAGE_MANAGER_EVENT_STATE_FAILED,
							  0,
							  PACKAGE_MANAGER_ERROR_NONE,
							  manager->user_data);
		}
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_set_event_status(package_manager_h manager, int status_type)
{
	int retval;

	if (manager == NULL){
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_client_set_status_type(manager->pc, status_type);

	if (retval < 0){
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_set_event_cb(package_manager_h manager,
				 package_manager_event_cb callback,
				 void *user_data)
{
	int retval;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if (package_manager_validate_handle(manager)) {
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	manager->event_cb = callback;
	manager->user_data = user_data;

    pkgmgr_client_listen_status(manager->pc, global_event_handler, manager);

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_unset_event_cb(package_manager_h manager)
{
	// TODO: Please implement this function.
	if (package_manager_validate_handle(manager)) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_get_package_id_by_app_id(const char *app_id, char **package_id)
{
	pkgmgrinfo_appinfo_h pkgmgrinfo_appinfo;
	int retval;
	char *pkg_id = NULL;
	char *pkg_id_dup = NULL;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if (app_id == NULL) {
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_appinfo_get_appinfo(app_id, &pkgmgrinfo_appinfo) != PMINFO_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo, &pkg_id);
	if (retval != PMINFO_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	pkg_id_dup = strdup(pkg_id);
	if (pkg_id_dup == NULL)
	{
		pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

	*package_id = pkg_id_dup;

	pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_get_package_info(const char *package_id, package_info_h *package_info)
{
	int retval;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	retval = package_info_get_package_info(package_id, package_info);

	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(retval, __FUNCTION__, NULL);
	}
	else
	{
		return PACKAGE_MANAGER_ERROR_NONE;
	}
}

int package_manager_foreach_package_info(package_manager_package_info_cb callback,
					void *user_data)
{
	int retval;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	retval = package_info_foreach_package_info(callback, user_data);

	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(retval, __FUNCTION__, NULL);
	}
	else
	{
		return PACKAGE_MANAGER_ERROR_NONE;
	}
}
int package_manager_compare_package_cert_info(const char *lhs_package_id, const char *rhs_package_id, package_manager_compare_result_type_e *compare_result)
{
	pkgmgrinfo_cert_compare_result_type_e result;

	if (lhs_package_id == NULL || rhs_package_id == NULL || compare_result == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_compare_pkg_cert_info(lhs_package_id, rhs_package_id, &result) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	*compare_result = (package_manager_compare_result_type_e)result;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, package_manager_compare_result_type_e *compare_result)
{
	pkgmgrinfo_cert_compare_result_type_e result;

	if (lhs_app_id == NULL || rhs_app_id == NULL || compare_result == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_compare_app_cert_info(lhs_app_id, rhs_app_id, &result) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	*compare_result = (package_manager_compare_result_type_e)result;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_is_preload_package_by_app_id(const char *app_id, bool *preload)
{
	pkgmgrinfo_appinfo_h pkgmgrinfo_appinfo = NULL;
	pkgmgrinfo_pkginfo_h pkgmgrinfo_pkginfo = NULL;

	int retval =0;
	char *pkg_id = NULL;
	bool is_preload = 0;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if (pkgmgrinfo_appinfo_get_appinfo(app_id, &pkgmgrinfo_appinfo) != PMINFO_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo, &pkg_id);
	if (retval != PMINFO_R_OK)
	{
		pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_pkginfo(pkg_id, &pkgmgrinfo_pkginfo) != PMINFO_R_OK)
	{
		pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo);
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_is_preload(pkgmgrinfo_pkginfo, &is_preload) != PMINFO_R_OK)
	{
		pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo);
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	if (is_preload)
		*preload = 1;
	else
		*preload = 0;

	pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo);

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_get_permission_type(const char *app_id, package_manager_permission_type_e *permission_type)
{
	int retval = 0;
	pkgmgrinfo_appinfo_h pkgmgrinfo_appinfo =NULL;
	pkgmgrinfo_permission_type permission = 0;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if (pkgmgrinfo_appinfo_get_appinfo(app_id, &pkgmgrinfo_appinfo) != PMINFO_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_appinfo_get_permission_type(pkgmgrinfo_appinfo, &permission);
	if (retval != PMINFO_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	if (permission == PMINFO_PERMISSION_NORMAL)
		*permission_type = PACKAGE_MANAGER_PERMISSION_NORMAL;
	else if (permission == PMINFO_PERMISSION_SIGNATURE)
		*permission_type = PACKAGE_MANAGER_PERMISSION_SIGNATURE;
	else if (permission == PMINFO_PERMISSION_PRIVILEGE)
		*permission_type = PACKAGE_MANAGER_PERMISSION_PRIVILEGE;
	else
		*permission_type = PACKAGE_MANAGER_PERMISSION_NORMAL;

	pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_clear_cache_dir(const char *package_id)
{
	int res = pkgmgr_client_clear_cache_dir(package_id);
	if (res == PKGMGR_R_EINVAL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_ENOPKG)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_ENOMEM)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_EIO)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_EPRIV)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_ESYSTEM || res == PKGMGR_R_ECOMM || res == PKGMGR_R_ERROR)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}
	else if (res != PKGMGR_R_OK)
	{
		_LOGE("Unexpected error");
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_clear_all_cache_dir(void)
{
	return package_manager_clear_cache_dir(PKG_CLEAR_ALL_CACHE);
}

static void __free_data(gpointer data)
{
	if (data)
	{
		free(data);
		data = NULL;
	}
}

static void __initialize_cb_table(void)
{
	__cb_table = g_hash_table_new_full(g_int_hash, g_int_equal, __free_data, NULL);
}

static void __result_cb(pkgmgr_client *pc, const char *pkgid, const pkg_size_info_t *result, void *user_data)
{
	int key = (int *)pc;

	package_manager_size_info_receive_cb callback = g_hash_table_lookup(__cb_table, &key);
	if (callback == NULL)
	{
		_LOGE("callback is null.");
		g_hash_table_remove(__cb_table, pc);
		pkgmgr_client_free(pc);
		return;
	}

	package_size_info_t size_info;
	size_info.data_size  = result->data_size;
	size_info.cache_size = result->cache_size;
	size_info.app_size   = result->app_size;
	size_info.external_data_size  = result->ext_data_size;
	size_info.external_cache_size = result->ext_cache_size;
	size_info.external_app_size   = result->ext_app_size;

	callback(pkgid, &size_info, user_data);

	g_hash_table_remove(__cb_table, pc);
	pkgmgr_client_free(pc);
}

static void __total_result_cb(pkgmgr_client *pc, const pkg_size_info_t *result, void *user_data)
{
	int key = (int *)pc;

	package_manager_total_size_info_receive_cb callback = g_hash_table_lookup(__cb_table, &key);
	if (callback == NULL)
	{
		_LOGE("callback is null.");
		g_hash_table_remove(__cb_table, pc);
		pkgmgr_client_free(pc);
		return;
	}

	package_size_info_t size_info;
	size_info.data_size  = result->data_size;
	size_info.cache_size = result->cache_size;
	size_info.app_size   = result->app_size;
	size_info.external_data_size  = result->ext_data_size;
	size_info.external_cache_size = result->ext_cache_size;
	size_info.external_app_size   = result->ext_app_size;

	callback(&size_info, user_data);

	g_hash_table_remove(__cb_table, pc);
	pkgmgr_client_free(pc);
}

int package_manager_get_package_size_info(const char *package_id, package_manager_size_info_receive_cb callback, void *user_data)
{
	if (package_id == NULL || callback == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (__cb_table == NULL)
	{
		__initialize_cb_table();
	}

	pkgmgr_client *pc = pkgmgr_client_new(PC_REQUEST);
	if (pc == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}

	int res = 0;
	if (strcmp(package_id, PKG_SIZE_INFO_TOTAL) != 0)
	{
		res = pkgmgr_client_get_package_size_info(pc, package_id, __result_cb, user_data);
	}
	else
	{
		res = pkgmgr_client_get_total_package_size_info(pc, __total_result_cb, user_data);
	}

	if (res == PKGMGR_R_EINVAL)
	{
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_ENOPKG)
	{
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_ENOMEM)
	{
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_EIO)
	{
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_EPRIV)
	{
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);
	}
	else if (res == PKGMGR_R_ESYSTEM || res == PKGMGR_R_ECOMM || res == PKGMGR_R_ERROR)
	{
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}
	else if (res != PKGMGR_R_OK)
	{
		_LOGE("Unexpected error");
		pkgmgr_client_free(pc);
		return package_manager_error(PACKAGE_MANAGER_ERROR_SYSTEM_ERROR, __FUNCTION__, NULL);
	}

	int *key = malloc(sizeof(int));
	*key = pc;
	g_hash_table_insert(__cb_table, key, callback);

	_LOGD("Successful");
	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_get_total_package_size_info(package_manager_total_size_info_receive_cb callback, void *user_data)
{
	return package_manager_get_package_size_info(PKG_SIZE_INFO_TOTAL, callback, user_data);
}

int package_manager_filter_create(package_manager_filter_h *handle)
{
	int retval;
	package_manager_filter_h created_filter = NULL;
	pkgmgrinfo_pkginfo_filter_h pkgmgr_filter = NULL;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if (handle == NULL)
	{
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	retval = pkgmgrinfo_pkginfo_filter_create(&pkgmgr_filter);
	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	created_filter = malloc(sizeof(struct package_manager_filter_s));
	if (created_filter == NULL)
	{
		pkgmgrinfo_pkginfo_filter_destroy(pkgmgr_filter);
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

	created_filter->pkgmgrinfo_pkginfo_filter = pkgmgr_filter;

	*handle = created_filter;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_filter_destroy(package_manager_filter_h handle)
{
	int retval;

	if (handle == NULL)
	{
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	retval = pkgmgrinfo_pkginfo_filter_destroy(handle->pkgmgrinfo_pkginfo_filter);
	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	free(handle);
	return PACKAGE_MANAGER_ERROR_NONE;
}
int package_manager_filter_add_bool(package_manager_filter_h handle,
		const char *property, const bool value)
{
	int retval;

	if ((handle == NULL) || (property == NULL))
	{
		return
		    package_manager_error
		    (PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__,
		     NULL);
	}

	retval = pkgmgrinfo_pkginfo_filter_add_bool(handle->pkgmgrinfo_pkginfo_filter, property, value);
	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_filter_count(package_manager_filter_h handle, int *count)
{
	int retval = 0;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	if ((handle == NULL) || (count == NULL))
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_pkginfo_filter_count(handle->pkgmgrinfo_pkginfo_filter, count);
	if (retval < 0)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_manager_filter_foreach_package_info(package_manager_filter_h handle,
		package_manager_package_info_cb callback, void *user_data)
{
	int retval;

	retval = check_privilege(PRIVILEGE_PACKAGE_MANAGER_INFO);
	if (retval != PACKAGE_MANAGER_ERROR_NONE) {
		return package_manager_error(retval, __FUNCTION__,
			 "failed to allow privilege");
	}

	retval = package_info_filter_foreach_package_info(handle->pkgmgrinfo_pkginfo_filter, callback, user_data);

	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(retval, __FUNCTION__, NULL);
	}
	else
	{
		return PACKAGE_MANAGER_ERROR_NONE;
	}
}

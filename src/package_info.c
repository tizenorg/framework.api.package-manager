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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <package-manager.h>
#include <pkgmgr-info.h>
#include <dlog.h>

#include <package_info.h>
#include <package_manager.h>


#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_PACKAGE_MANAGER"

struct package_info_s {
	char *package;
	pkgmgrinfo_pkginfo_h pkgmgrinfo_pkginfo;
};

struct package_cert_info_s {
	char *package;
	pkgmgrinfo_certinfo_h pkgmgrinfo_certinfo;
};

typedef struct _foreach_pkg_context_{
	package_manager_package_info_cb callback;
	void *user_data;
} foreach_pkg_context_s;


typedef struct _foreach_app_context_{
	package_info_app_cb callback;
	void *user_data;
} foreach_app_context_s;


int package_info_create(const char *package,  package_info_h *package_info)
{
	package_info_h package_info_created;
	pkgmgrinfo_pkginfo_h pkgmgrinfo_pkginfo;

	if (package == NULL || package_info == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_pkginfo(package, &pkgmgrinfo_pkginfo) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}

	package_info_created = calloc(1, sizeof(struct package_info_s));

	if (package_info_created == NULL)
	{
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo);
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

	package_info_created->package = strdup(package);

	if (package_info_created->package == NULL)
	{
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo);
		free(package_info_created);
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

	package_info_created->pkgmgrinfo_pkginfo = pkgmgrinfo_pkginfo;

	*package_info = package_info_created;

	return PACKAGE_MANAGER_ERROR_NONE;
}


int package_info_get_package_info(const char *package, package_info_h *package_info)
{
	return package_info_create(package, package_info);
}


static int package_info_foreach_package_info_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	char *pkg_name = NULL;
	foreach_pkg_context_s *foreach_pkg_context = user_data;
	package_info_h package_info = NULL;

	if (handle == NULL || foreach_pkg_context == NULL)
	{
		package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		return PKGMGR_R_EINVAL;
	}

	pkgmgrinfo_pkginfo_get_pkgname(handle, &pkg_name);

	if (package_info_create(pkg_name, &package_info) == PACKAGE_MANAGER_ERROR_NONE)
	{
		foreach_pkg_context->callback(package_info, foreach_pkg_context->user_data);
		package_info_destroy(package_info);
	}

	/* pkgmgr_get_info_list() needs to be enhanced to stop and continue callback */
	return PKGMGR_R_OK;
}


int package_info_foreach_package_info(package_manager_package_info_cb callback, void *user_data)
{
	foreach_pkg_context_s foreach_pkg_context = {
		.callback = callback,
		.user_data = user_data,
	};
	int ret = 0;

	if (callback == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	ret = pkgmgrinfo_pkginfo_get_list(package_info_foreach_package_info_cb, &foreach_pkg_context);
	if (ret < 0) {
		return PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE;
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_filter_foreach_package_info(pkgmgrinfo_pkginfo_filter_h handle, package_manager_package_info_cb callback, void *user_data)
{
	foreach_pkg_context_s foreach_pkg_context = {
		.callback = callback,
		.user_data = user_data,
	};
	int ret = 0;

	if ((handle == NULL) || (callback == NULL))
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, package_info_foreach_package_info_cb, &foreach_pkg_context);
	if (ret < 0) {
		return PACKAGE_MANAGER_ERROR_IO_ERROR;
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

static int package_info_foreach_app_cb (const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	pkgmgr_app_component comp;
	foreach_app_context_s *foreach_app_context = user_data;
	int ret = 0;

	if (handle == NULL || foreach_app_context == NULL)
	{
		package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		return PKGMGR_R_ERROR;
	}
	ret = pkgmgrinfo_appinfo_get_component(handle, &comp);
	if (ret < 0) {
		return PKGMGR_R_ERROR;
	}

	ret = foreach_app_context->callback(comp, appid, foreach_app_context->user_data);
	if (!ret)
	{
		package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
		return PKGMGR_R_ERROR;
	}

	return PKGMGR_R_OK;
}



int package_info_foreach_app_from_package(package_info_h package_info, package_info_app_component_type_e comp_type, package_info_app_cb callback, void *user_data)
{
	foreach_app_context_s foreach_app_context = {
		.callback = callback,
		.user_data = user_data,
	};
	pkgmgrinfo_pkginfo_h pkgmgrinfo_pkginfo;
	int ret = 0;

	if (package_info == NULL || callback == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_pkginfo(package_info->package, &pkgmgrinfo_pkginfo) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE, __FUNCTION__, NULL);
	}
	if (comp_type == PACKAGE_INFO_ALLAPP)
		ret = pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo, PM_ALL_APP, package_info_foreach_app_cb, &foreach_app_context);
	if (comp_type == PACKAGE_INFO_UIAPP)
		ret = pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo, PM_UI_APP, package_info_foreach_app_cb, &foreach_app_context);
	if (comp_type == PACKAGE_INFO_SERVICEAPP)
		ret = pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo, PM_SVC_APP, package_info_foreach_app_cb, &foreach_app_context);

	return ret;
}


int package_info_destroy(package_info_h package_info)
{
	if (package_info == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	free(package_info->package);

	pkgmgrinfo_pkginfo_destroy_pkginfo(package_info->pkgmgrinfo_pkginfo);

	free(package_info);

	package_info = NULL;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_package(package_info_h package_info, char **package)
{
	char *package_dup;

	if (package_info == NULL || package == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	package_dup = strdup(package_info->package);

	if (package_dup == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

	*package = package_dup;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_label(package_info_h package_info, char **label)
{
	char *pkg_info_value = NULL;
	char *label_dup = NULL;

	if (package_info == NULL || label == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_label(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	if(!pkg_info_value)
		goto END;

	label_dup = strdup(pkg_info_value);

	if (label_dup == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

END:
	*label = label_dup;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_icon(package_info_h package_info, char **path)
{
	char *pkg_info_value = NULL;
	char *icon_dup = NULL;

	if (package_info == NULL || path == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_icon(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	if(!pkg_info_value)
		goto END;

	icon_dup = strdup(pkg_info_value);

	if (icon_dup == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

END:
	*path = icon_dup;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_version(package_info_h package_info, char **version)
{
	char *pkg_info_value = NULL;
	char *ver_dup = NULL;

	if (package_info == NULL || version == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_version(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	if(!pkg_info_value)
		goto END;

	ver_dup = strdup(pkg_info_value);

	if (ver_dup == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

END:
	*version = ver_dup;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_type(package_info_h package_info, char **type)
{
	char *pkg_info_value = NULL;
	char *type_dup = NULL;

	if (package_info == NULL || type == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_type(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	if(!pkg_info_value)
		goto END;

	type_dup = strdup(pkg_info_value);

	if (type_dup == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

END:
	*type = type_dup;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_installed_storage(package_info_h package_info, package_info_installed_storage_type_e *storage)
{
	int ret = 0;
	pkgmgr_installed_storage pkg_info_value;

	if (package_info == NULL || storage == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	ret = pkgmgrinfo_pkginfo_get_installed_storage(package_info->pkgmgrinfo_pkginfo, &pkg_info_value);
	if (ret < 0)
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);

	if (pkg_info_value == PM_INTERNAL_STORAGE)
		*storage = PACKAGE_INFO_INTERNAL_STORAGE;
	else if (pkg_info_value == PM_EXTERNAL_STORAGE)
		*storage = PACKAGE_INFO_EXTERNAL_STORAGE;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_get_root_path(package_info_h package_info, char **path)
{
	char *pkg_info_value = NULL;
	char *path_dup = NULL;

	if (package_info == NULL || path == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_root_path(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	if(!pkg_info_value)
		goto END;

	path_dup = strdup(pkg_info_value);

	if (path_dup == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

END:
	*path = path_dup;

	return PACKAGE_MANAGER_ERROR_NONE;
}


/*
int package_info_get_install_location(package_info_h package_info, package_manager_package_location_e *location)
{
	pkgmgr_install_location pkg_info_value = 0;

	if (package_info == NULL || system == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_get_install_location(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	*location = (pkg_info_value==PM_INSTALL_LOCATION_INTERNAL_ONLY ? PACAKGE_MANAGER_LOCATION_INTERNAL : PACAKGE_MANAGER_LOCATION_EXTERNAL);

	return PACKAGE_MANAGER_ERROR_NONE;
}
*/

int package_info_is_system_package(package_info_h package_info, bool *system)
{
	bool pkg_info_value = false;

	if (package_info == NULL || system == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_is_preload(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	*system = pkg_info_value;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_is_removable_package(package_info_h package_info, bool *removable)
{
	bool pkg_info_value = false;

	if (package_info == NULL || removable == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_is_removable(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	*removable = pkg_info_value;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_is_preload_package(package_info_h package_info, bool *preload)
{
	bool pkg_info_value = false;

	if (package_info == NULL || preload == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (pkgmgrinfo_pkginfo_is_preload(package_info->pkgmgrinfo_pkginfo, &pkg_info_value) != PKGMGR_R_OK)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	*preload = pkg_info_value;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_is_equal(package_info_h lhs, package_info_h rhs, bool *equal)
{
	if (lhs == NULL || rhs == NULL || equal == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	if (!strcmp(lhs->package, rhs->package))
	{
		*equal = true;
	}
	else
	{
		*equal = false;
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_is_accessible(package_info_h package_info, bool *accessible)
{
	int ret = 0;
	bool pkg_info_value = false;

	if (package_info == NULL || accessible == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	ret = pkgmgrinfo_pkginfo_is_accessible(package_info->pkgmgrinfo_pkginfo, &pkg_info_value);
	if (ret < 0)
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);


	*accessible = pkg_info_value;

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_clone(package_info_h *clone, package_info_h package_info)
{
	int retval;

	if (clone == NULL || package_info == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	retval = package_info_create(package_info->package, clone);

	if (retval != PACKAGE_MANAGER_ERROR_NONE)
	{
		return package_manager_error(retval, __FUNCTION__, NULL);
	}

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_foreach_cert_info(package_info_h package_info, package_info_cert_info_cb callback, void* user_data)
{
	int retval;
	pkgmgrinfo_certinfo_h handle = NULL;
	int i = 0;
	const char *cert_value = NULL;

	if (package_info == NULL || callback == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_pkginfo_create_certinfo(&handle);
	if (retval != PMINFO_R_OK)
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);

	retval = pkgmgrinfo_pkginfo_load_certinfo(package_info->package, handle);
	if (retval != PMINFO_R_OK)
	{
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
		return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	for( i=0; i<=PACKAGE_INFO_DISTRIBUTOR2_SIGNER_CERT; i++)
	{
		retval = pkgmgrinfo_pkginfo_get_cert_value(handle, i, &cert_value);
		if (retval != PMINFO_R_OK)
		{
			pkgmgrinfo_pkginfo_destroy_certinfo(handle);
			return package_manager_error(PACKAGE_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
		}

		if ( cert_value && strncmp(cert_value, "(null)", strlen("(null)")) )
		{
			retval = callback(package_info, (package_cert_type_e)i, cert_value, user_data);
			if (!retval)
				break;
		}

		cert_value = NULL;
	}

	pkgmgrinfo_pkginfo_destroy_certinfo(handle);

	return PACKAGE_MANAGER_ERROR_NONE;
}

int package_info_foreach_privilege_info(package_info_h package_info, package_info_privilege_info_cb callback, void *user_data)
{
	int ret = 0;

	if (package_info == NULL || callback == NULL)
	{
		return package_manager_error(PACKAGE_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
	}

	ret = pkgmgrinfo_pkginfo_foreach_privilege(package_info->pkgmgrinfo_pkginfo, callback, user_data);

	return ret;
}

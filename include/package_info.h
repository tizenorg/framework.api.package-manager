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


#ifndef __TIZEN_APPFW_PACKAGE_INFO_H
#define __TIZEN_APPFW_PACKAGE_INFO_H

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup CAPI_PACKAGE_INFO_MODULE
* @{
*/

/**
 * @brief Package information handle.
 */
 typedef struct package_info_s *package_info_h;

/**
 * @brief Enumeration of storage type
 */
typedef enum {
	PACKAGE_INFO_INTERNAL_STORAGE = 0,
	PACKAGE_INFO_EXTERNAL_STORAGE = 1,
} package_info_installed_storage_type_e;

typedef enum {
	PACKAGE_INFO_ALLAPP = 0,
	PACKAGE_INFO_UIAPP = 1,
	PACKAGE_INFO_SERVICEAPP = 2,
} package_info_app_component_type_e;

typedef enum {
	PACKAGE_INFO_AUTHOR_ROOT_CERT = 0,			/**< Author Root Certificate*/
	PACKAGE_INFO_AUTHOR_INTERMEDIATE_CERT = 1,		/**< Author Intermediate Certificate*/
	PACKAGE_INFO_AUTHOR_SIGNER_CERT = 2,			/**< Author Signer Certificate*/
	PACKAGE_INFO_DISTRIBUTOR_ROOT_CERT = 3,			/**< Distributor Root Certificate*/
	PACKAGE_INFO_DISTRIBUTOR_INTERMEDIATE_CERT = 4,		/**< Distributor Intermediate Certificate*/
	PACKAGE_INFO_DISTRIBUTOR_SIGNER_CERT = 5,		/**< Distributor Signer Certificate*/
	PACKAGE_INFO_DISTRIBUTOR2_ROOT_CERT = 6,		/**< Distributor2 Root Certificate*/
	PACKAGE_INFO_DISTRIBUTOR2_INTERMEDIATE_CERT = 7,	/**< Distributor2 Intermediate Certificate*/
	PACKAGE_INFO_DISTRIBUTOR2_SIGNER_CERT = 8,		/**< Distributor2 Signer Certificate*/
} package_cert_type_e;


/**
 * @brief Called to get the application id once for each installed package.
 * @param [in] comp_type The Application Component type
 * @param [in] callback The callback function to invoke
 * @param [in] user_data The user data passed from the foreach function
 * @return @c true to continue with the next iteration of the loop, \n @c false to break out of the loop.
 * @pre package_info_foreach_app_from_package() will invoke this callback.
 * @see package_info_foreach_app_from_package()
 */
/*This callback is not fixed, Don't use it now */
typedef bool (*package_info_app_cb) (package_info_app_component_type_e comp_type, const char *app_id, void *user_data);


/**
 * @brief Called to get the certification information
 * @param [in] package_info The package info handle
 * @param [in] cert_type The certificate type
 * @param [in] cert_value The certificate value of corresponding certificate key. This value is base64 encoded data
 * @param [in] user_data The user data passed from the foreach function
 * @return @c true to continue with the next iteration of the loop, \n @c false to break out of the loop.
 * @pre package_info_foreach_cert_info() will invoke this callback.
 * @see package_info_foreach_cert_info()
 */
typedef bool (*package_info_cert_info_cb) (package_info_h handle, package_cert_type_e cert_type, const char *cert_value, void *user_data);


/**
 * @brief Retrieves all application id of each package
 * @param [in] package_info The package info handle
 * @param [in] comp_type The application component type
 * @param [in] callback The callback function to invoke
 * @param [in] user_data The user data to be passed to the callback function
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE No such package
 * @post	This function invokes package_info_app_cb() repeatedly for each package.
 * @see package_info_app_cb()
 */
/*This API is not fixed, Don't use it now */
int package_info_foreach_app_from_package(package_info_h package_info, package_info_app_component_type_e comp_type, package_info_app_cb callback, void *user_data);


/**
 * @brief Destroys the package information handle and releases all its resources.
 * @param [in] package_info The package information handle
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @see package_manager_foreach_package_info()
 * @see package_manager_get_package_info()
 */
int package_info_destroy(package_info_h package_info);


/**
 * @brief Gets the absolute path to the icon image
 * @remarks @a package must be released with free() by you.
 * @param [in] package_info The package information
 * @param [out] package The package name
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 */
int package_info_get_package(package_info_h package_info, char **package);


/**
 * @brief Gets the label of the package
 * @remarks @a label must be released with free() by you.
 * @param [in] package_info The package information
 * @param [out] name The label of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_get_label(package_info_h package_info, char **label);


/**
 * @brief Gets the absolute path to the icon image
 * @remarks @a path must be released with free() by you.
 * @param [in] package_info The package information
 * @param [out] path The path of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_get_icon(package_info_h package_info, char **path);


/**
 * @brief Gets the version of the package
 * @remarks @a version must be released with free() by you.
 * @param [in] package_info The package information
 * @param [out] path The version of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_get_version(package_info_h package_info, char **version);


/**
 * @brief Gets the type of the package
 * @remarks @a type must be released with free() by you.
 * @param [in] package_info The package information
 * @param [out] version The type of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_get_type(package_info_h package_info, char **type);


/**
 * @brief Gets the installed storage for the given package
 * @param [in] package_info The package information
 * @param[out] storage		The installed storage
 * @return  0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 */
int package_info_get_installed_storage(package_info_h package_info, package_info_installed_storage_type_e *storage);


/**
 * @brief Gets the root path of the package
 * @remarks @a path must be released with free() by you.
 * @param [in] package_info The package information
 * @param [out] path The root path of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_get_root_path(package_info_h package_info, char **path);

/**
 * @brief Gets whether the package is system package or not
 * @param [in] package_info The package information
 * @param [out] system The system info of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_is_system_package(package_info_h package_info, bool *system);


/**
 * @brief Gets whether the package is removable or not
 * @param [in] package_info The package information
 * @param [out] removable The removable info of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_is_removable_package(package_info_h package_info, bool *removable);


/**
 * @brief Gets whether the package is preload or not
 * @param [in] package_info The package information
 * @param [out] preload The preload info of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_is_preload_package(package_info_h package_info, bool *preload);


/**
 * @brief Checks whether two package information are equal.
 * @param [in] lhs	The first package information to compare
 * @param [in] rhs	The second package information to compare
 * @param [out] equal true if the package information are equal, otherwise false
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Database error occurred
 */
int package_info_is_equal(package_info_h lhs, package_info_h rhs, bool *equal);


/**
 * @brief Gets the package accessible for the given package
 * @param [in] package_info The package information
 * @param[out] accessible		If the given package can access, it returns ture. If it is not, it returns false
 * @return  0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 */
int package_info_is_accessible(package_info_h package_info, bool *accessible);


/**
 * @brief Clones the package information handle.
 * @param [out] clone If successful, a newly created package information handle will be returned.
 * @param [in] package_info_h The package information
 * @return 0 on success, otherwise a negative error value.
 * @retval #APP_MANAGER_ERROR_NONE Successful
 * @retval #APP_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #APP_MANAGER_ERROR_DB_FAILED Database error occurred
 * @retval #APP_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 */
int package_info_clone(package_info_h *clone, package_info_h package_info);


/**
 * @brief Retrieves certification information of the package
 * @param [in] package_info The package information
 * @param [in] callback The iteration callback function
 * @param [in] user_data The user data to be passed to the callback function
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_info_foreach_cert_info(package_info_h package_info, package_info_cert_info_cb callback, void* user_data);


/**
 * @brief Gets the package information for the given package
 * @remarks @a package_info must be released with package_info_destroy() by you.
 * @param [in] package The ID of the package
 * @param [out] package_info The package information for the given package ID
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Database error occurred
 */
int package_info_create(const char *package,  package_info_h *package_info);


/**
* @}
*/

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_PACKAGE_INFO_H */

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
 * @file package_info.h
 */

/**
 * @addtogroup CAPI_PACKAGE_INFO_MODULE
 * @{
 */

/**
 * @brief The package information handle.
 * @since_tizen 2.3
 */
 typedef struct package_info_s *package_info_h;

/**
 * @brief Enumeration for storage type.
 * @since_tizen 2.3
 */
typedef enum {
    PACKAGE_INFO_INTERNAL_STORAGE = 0,    /**< Internal storage */
    PACKAGE_INFO_EXTERNAL_STORAGE = 1,    /**< External storage */
} package_info_installed_storage_type_e;

/**
 * @brief Enumeration for app component type.
 * @since_tizen 2.3
 */
typedef enum {
    PACKAGE_INFO_ALLAPP = 0,        /**< All application */
    PACKAGE_INFO_UIAPP = 1,         /**< UI application */
    PACKAGE_INFO_SERVICEAPP = 2,    /**< Service application */
} package_info_app_component_type_e;

/**
 * @brief Enumeration for certification type.
 * @since_tizen 2.3
 */
typedef enum {
    PACKAGE_INFO_AUTHOR_ROOT_CERT = 0,               /**< Author Root Certificate*/
    PACKAGE_INFO_AUTHOR_INTERMEDIATE_CERT = 1,       /**< Author Intermediate Certificate*/
    PACKAGE_INFO_AUTHOR_SIGNER_CERT = 2,             /**< Author Signer Certificate*/
    PACKAGE_INFO_DISTRIBUTOR_ROOT_CERT = 3,          /**< Distributor Root Certificate*/
    PACKAGE_INFO_DISTRIBUTOR_INTERMEDIATE_CERT = 4,  /**< Distributor Intermediate Certificate*/
    PACKAGE_INFO_DISTRIBUTOR_SIGNER_CERT = 5,        /**< Distributor Signer Certificate*/
    PACKAGE_INFO_DISTRIBUTOR2_ROOT_CERT = 6,         /**< Distributor2 Root Certificate*/
    PACKAGE_INFO_DISTRIBUTOR2_INTERMEDIATE_CERT = 7, /**< Distributor2 Intermediate Certificate*/
    PACKAGE_INFO_DISTRIBUTOR2_SIGNER_CERT = 8,       /**< Distributor2 Signer Certificate*/
} package_cert_type_e;

/**
 * @brief Called to get the application ID once for each installed package.
 * @since_tizen 2.3
 *
 * @param[in] comp_type  The Application Component type
 * @param[in] callback   The callback function to be invoked
 * @param[in] user_data  The user data passed from the foreach function
 *
 * @return  @c true to continue with the next iteration of the loop,
 *          otherwise @c false to break out of the loop
 *
 * @pre package_info_foreach_app_from_package() will invoke this callback.
 * @see package_info_foreach_app_from_package()
 */
typedef bool (*package_info_app_cb) (package_info_app_component_type_e comp_type, const char *app_id, void *user_data);

/**
 * @brief Called to get the certification information.
 * @since_tizen 2.3
 *
 * @param[in] package_info The package info handle
 * @param[in] cert_type    The certificate type
 * @param[in] cert_value   The certificate value of corresponding certificate key \n
 *                         This value is base64 encoded data.
 * @param[in] user_data    The user data passed from the foreach function
 *
 * @return  @c true to continue with the next iteration of the loop,
 *          otherwise @c false to break out of the loop
 *
 * @pre package_info_foreach_cert_info() will invoke this callback.
 *
 * @see package_info_foreach_cert_info()
 */
typedef bool (*package_info_cert_info_cb) (package_info_h handle, package_cert_type_e cert_type, const char *cert_value, void *user_data);

/**
 * @brief Called to get the privilege information.
 * @since_tizen 2.3
 *
 * @param[in] privilege_name the name of the privilege
 * @param[in] user_data    The user data passed from the foreach function
 *
 * @return  @c true to continue with the next iteration of the loop,
 *          otherwise @c false to break out of the loop
 *
 * @pre package_info_foreach_privilege_info() will invoke this callback.
 *
 * @see package_info_foreach_privilege_info()
 */
typedef bool (*package_info_privilege_info_cb) (const char *privilege_name, void *user_data);

/**
 * @brief Retrieves all application IDs of each package.
 * @since_tizen 2.3
 *
 * @param[in] package_info  The package info handle
 * @param[in] comp_type     The application component type
 * @param[in] callback      The callback function to invoke
 * @param[in] user_data     The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   No such package
 *
 * @post  This function invokes package_info_app_cb() repeatedly for each package.
 *
 * @see package_info_app_cb()
 */
int package_info_foreach_app_from_package(package_info_h package_info, package_info_app_component_type_e comp_type, package_info_app_cb callback, void *user_data);

/**
 * @brief Destroys the package information handle and releases all its resources.
 * @since_tizen 2.3
 *
 * @param[in] package_info The package information handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see package_manager_foreach_package_info()
 * @see package_manager_get_package_info()
 */
int package_info_destroy(package_info_h package_info);

/**
 * @brief Gets the package name.
 * @since_tizen 2.3
 *
 * @remarks You must release @a package using free().
 *
 * @param[in]  package_info The package information
 * @param[out] package      The package name
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 */
int package_info_get_package(package_info_h package_info, char **package);

/**
 * @brief Gets the label of the package.
 * @since_tizen 2.3
 *
 * @remarks You must release @a label using free().
 *
 * @param[in]  package_info The package information
 * @param[out] label        The label of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_get_label(package_info_h package_info, char **label);

/**
 * @brief Gets the absolute path to the icon image.
 * @since_tizen 2.3
 *
 * @remarks You must release @a path using free().
 *
 * @param[in]  package_info The package information
 * @param[out] path         The path of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_get_icon(package_info_h package_info, char **path);

/**
 * @brief Gets the version of the package.
 * @since_tizen 2.3
 *
 * @remarks You must release @a version using free().
 *
 * @param[in]  package_info The package information
 * @param[out] version      The version of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_get_version(package_info_h package_info, char **version);

/**
 * @brief Gets the type of the package.
 * @since_tizen 2.3
 *
 * @remarks You must release @a type using free().
 *
 * @param[in]  package_info The package information
 * @param[out] type         The type of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_get_type(package_info_h package_info, char **type);

/**
 * @brief Gets the installed storage for the given package.
 * @since_tizen 2.3
 *
 * @param[in]  package_info The package information
 * @param[out] storage      The installed storage
 *
 * @return  @c 0 on success,
 *          otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 */
int package_info_get_installed_storage(package_info_h package_info, package_info_installed_storage_type_e *storage);

/**
 * @brief Gets the root path of the package.
 * @since_tizen 2.3
 *
 * @remarks You must release @a path using free().
 *
 * @param[in]  package_info The package information
 * @param[out] path         The root path of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_get_root_path(package_info_h package_info, char **path);

/**
 * @brief Checks whether the package is system package.
 * @since_tizen 2.3
 *
 * @param[in]  package_info The package information
 * @param[out] system       @c true if the package is system package,
 *                          otherwise @c false if the package is not system package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_is_system_package(package_info_h package_info, bool *system);

/**
 * @brief Checks whether the package is removable.
 * @since_tizen 2.3
 *
 * @param[in]  package_info The package information
 * @param[out] removable    The removable info of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_is_removable_package(package_info_h package_info, bool *removable);

/**
 * @brief Checks whether the package is preloaded.
 * @since_tizen 2.3
 *
 * @param[in]  package_info The package information
 * @param[out] preload      The preload info of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_is_preload_package(package_info_h package_info, bool *preload);

/**
 * @brief Checks whether two package information are equal.
 * @since_tizen 2.3
 *
 * @param[in]  lhs    The first package information to be compared
 * @param[in]  rhs    The second package information to be compared
 * @param[out] equal  @c true if the package information are equal,
 *                    otherwise @c false if package information are not equal
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          Database error occurred
 */
int package_info_is_equal(package_info_h lhs, package_info_h rhs, bool *equal);

/**
 * @brief Checks whether the package info is accessible for the given package.
 * @since_tizen 2.3
 *
 * @param[in]  package_info The package information
 * @param[out] accessible   @c true if the package info is accessible,
 *                          otherwise @c false if the package info is not accessible
 *
 * @return  @c 0 on success,
 *          otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 */
int package_info_is_accessible(package_info_h package_info, bool *accessible);

/**
 * @brief Clones the package information handle.
 * @since_tizen 2.3
 *
 * @param[out] clone          The newly created package information handle
 * @param[in]  package_info   The package information
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   The package is not installed
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 */
int package_info_clone(package_info_h *clone, package_info_h package_info);

/**
 * @brief Gets the package information for the given package
 * @since_tizen 2.3
 *
 * @remarks You must release @a package_info using package_info_destroy().
 *
 * @param[in]  package      The ID of the package
 * @param[out] package_info The package information for the given package ID
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   The package is not installed
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 */
int package_info_create(const char *package,  package_info_h *package_info);

/**
 * @brief Retrieves certification information of the package.
 * @since_tizen 2.3
 *
 * @param[in] package_info The package information
 * @param[in] callback     The iteration callback function
 * @param[in] user_data    The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_foreach_cert_info(package_info_h package_info, package_info_cert_info_cb callback, void* user_data);

/**
 * @brief Retrieves privilege information of the package.
 * @since_tizen 2.3
 *
 * @param[in] package_info The package information
 * @param[in] callback     The iteration callback function
 * @param[in] user_data    The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 */
int package_info_foreach_privilege_info(package_info_h package_info, package_info_privilege_info_cb callback, void* user_data);

/**
* @}
*/

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_PACKAGE_INFO_H */

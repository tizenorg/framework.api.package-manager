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

#ifndef __TIZEN_APPFW_PACKAGE_MANAGER_H
#define __TIZEN_APPFW_PACKAGE_MANAGER_H

#include <tizen.h>

#include <package_info.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file package_manager.h
 */

/**
 * @addtogroup CAPI_PACKAGE_MANAGER_MODULE
 * @{
 */

/**
 * @brief Value to be used when filtering based on install location: Boolean property for filtering whether the package is removable or not based on package info
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
#define PACKAGE_MANAGER_PKGINFO_PROP_REMOVABLE       "PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE"

/**
 * @brief Value to be used when filtering based on install location: Boolean property for filtering whether the package is readonly or not based on package info
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
#define PACKAGE_MANAGER_PKGINFO_PROP_READONLY        "PMINFO_PKGINFO_PROP_PACKAGE_READONLY"

/**
 * @brief Value to be used when filtering based on install location: Boolean property for filtering whether the package supports disable or not based on package info
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
#define PACKAGE_MANAGER_PKGINFO_PROP_SUPPORT_DISABLE     "PMINFO_PKGINFO_PROP_PACKAGE_SUPPORT_DISABLE"

/**
 * @brief Value to be used when filtering based on install location: Boolean property for filtering whether the package is disabled based on package info
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
#define PACKAGE_MANAGER_PKGINFO_PROP_DISABLE             "PMINFO_PKGINFO_PROP_PACKAGE_DISABLE"

/**
 * @brief Value to be used when filtering based on install location: Boolean property for filtering whether the package is preload or not based on package info
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
#define PACKAGE_MANAGER_PKGINFO_PROP_PRELOAD		"PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD"

/**
 * @brief Enumeration for error code.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
	PACKAGE_MANAGER_ERROR_NONE = TIZEN_ERROR_NONE,                                /**< Successful */
	PACKAGE_MANAGER_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,      /**< Invalid parameter */
	PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,              /**< Out of memory */
	PACKAGE_MANAGER_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR,                        /**< Internal I/O error */
	PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE = TIZEN_ERROR_PACKAGE_MANAGER | 0x71,   /**< No such package */
	PACKAGE_MANAGER_ERROR_SYSTEM_ERROR = TIZEN_ERROR_PACKAGE_MANAGER | 0x72,      /**< Severe system error */
	PACKAGE_MANAGER_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED       /**< Permisson denied */
} package_manager_error_e;

/**
 * @brief Enumeration for event type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_EVENT_TYPE_INSTALL = 0,    /**< Install event type */
    PACKAGE_MANAGER_EVENT_TYPE_UNINSTALL,      /**< Uninstall event type */
    PACKAGE_MANAGER_EVENT_TYPE_UPDATE,         /**< Update event type */
} package_manager_event_type_e;

/**
 * @brief Enumeration for event state.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_EVENT_STATE_STARTED = 0,   /**< Started event state */
    PACKAGE_MANAGER_EVENT_STATE_PROCESSING,    /**< Processing event state */
    PACKAGE_MANAGER_EVENT_STATE_COMPLETED,     /**< Completed event state */
    PACKAGE_MANAGER_EVENT_STATE_FAILED,        /**< Failed event state */
} package_manager_event_state_e;

/**
 * @internal
 * @brief Enumeration for request mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_REQUEST_MODE_DEFAULT = 0,    /**< @internal Default request mode */
    PACKAGE_MANAGER_REQUEST_MODE_QUIET,          /**< @internal Quiet request mode */
} package_manager_request_mode_e;

/**
 * @brief Enumeration for move type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_REQUEST_MOVE_TO_INTERNAL = 0,    /**< Internal type */
    PACKAGE_MANAGER_REQUEST_MOVE_TO_EXTERNAL,        /**< External type */
} package_manager_move_type_e;

/**
 * @brief Enumeration for certification compare type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_COMPARE_MATCH = 0,      /**< Matching certification */
    PACKAGE_MANAGER_COMPARE_MISMATCH,       /**< Mismatching certification */
    PACKAGE_MANAGER_COMPARE_LHS_NO_CERT,    /**< First package has no certification */
    PACKAGE_MANAGER_COMPARE_RHS_NO_CERT,    /**< Second package has no certification */
    PACKAGE_MANAGER_COMPARE_BOTH_NO_CERT,   /**< Both have no certification */
} package_manager_compare_result_type_e;

/**
 * @brief Enumeration for permission type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_PERMISSION_NORMAL = 0,    /**< Normal permission */
    PACKAGE_MANAGER_PERMISSION_SIGNATURE,     /**< Signature permission */
    PACKAGE_MANAGER_PERMISSION_PRIVILEGE,     /**< Privilege permission */
} package_manager_permission_type_e;

/**
 * @brief Enumeration for status type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum {
    PACKAGE_MANAGER_STATUS_TYPE_ALL = 0x00,               /**< All status */
    PACKAGE_MANAGER_STATUS_TYPE_INSTALL = 0x01,           /**< Install package status */
    PACKAGE_MANAGER_STATUS_TYPE_UNINSTALL = 0x02,         /**< Uninstall package status */
    PACKAGE_MANAGER_STATUS_TYPE_UPGRADE = 0x04,           /**< Upgrade package status */
    PACKAGE_MANAGER_STATUS_TYPE_MOVE = 0x08,              /**< Move package status */
    PACKAGE_MANAGER_STATUS_TYPE_CLEAR_DATA = 0x10,        /**< Clear data status */
    PACKAGE_MANAGER_STATUS_TYPE_INSTALL_PROGRESS = 0x20,  /**< Install progress status */
    PACKAGE_MANAGER_STATUS_TYPE_GET_SIZE = 0x40,          /**< Get size status */
} package_manager_status_type_e;

/**
 * @brief The Package manager handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef struct package_manager_s *package_manager_h;

/**
 * @brief Package manager filter handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef struct package_manager_filter_s *package_manager_filter_h;

/**
 * @internal
 * @brief The Package manager request handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef struct package_manager_request_s *package_manager_request_h;

/**
 * @internal
 * @brief Called when the progress of the request to the package manager changes.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] id          The ID of the request to the package manager
 * @param[in] type        The type of the package to install, uninstall or update
 * @param[in] package     The name of the package to install, uninstall or update
 * @param[in] event_type  The type of the request to the package manager
 * @param[in] event_state The current state of the request to the package manager
 * @param[in] progress    The progress for the request that is being processed by the package manager \n
 *                        The range of progress is from @c 0 to @c 100.
 * @param[in] error       The error code when the package manager failed to process the request
 * @param[in] user_data   The user data passed from package_manager_request_set_event_cb()
 *
 * @see package_manager_request_set_event_cb()
 * @see package_manager_request_unset_event_cb()
 */
typedef void (*package_manager_request_event_cb) (
            int id,
            const char *type,
            const char *package,
            package_manager_event_type_e event_type,
            package_manager_event_state_e event_state,
            int progress,
            package_manager_error_e error,
            void *user_data);

/**
 * @internal
 * @brief Creates a request handle to the package manager.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @remarks You must release @a request using package_manager_request_destroy().
 *
 * @param[out] request The request handle that is newly created on success
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          Internal I/O error
 *
 * @see package_manager_request_destroy()
 */
int package_manager_request_create(package_manager_request_h *request);

/**
 * @internal
 * @brief Destroys the request handle to the package manager.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] request The request handle to the package manager
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see package_manager_request_create()
 */
int package_manager_request_destroy(package_manager_request_h request);

/**
 * @internal
 * @brief Registers a callback function to be invoked when the progress of the request changes.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @param[in] request The request handle
 * @param[in] callback The callback function to be registered
 * @param[in] user_data The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @post package_manager_request_event_cb() will be invoked.
 *
 * @see package_manager_request_event_cb()
 * @see package_manager_request_unset_event_cb()
 */
int package_manager_request_set_event_cb(package_manager_request_h request,
                     package_manager_request_event_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] request The request handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see package_manager_request_event_cb()
 * @see package_manager_request_set_event_cb()
 */
int package_manager_request_unset_event_cb(package_manager_request_h request);

/**
 * @internal
 * @brief Sets the type of the package to install, uninstall or update.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] request The request handle
 * @param[in] type    The type of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 */
int package_manager_request_set_type(package_manager_request_h request,
                     const char *type);

/**
 * @internal
 * @brief Sets the mode of the request.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] request The request handle
 * @param[in] mode    The mode of the request
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 */
int package_manager_request_set_mode(package_manager_request_h request,
                     package_manager_request_mode_e mode);

/**
 * @internal
 * @brief Installs the package located at the given path.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/packagemanager.admin
 * @param[in]  request The request handle
 * @param[in]  path    The absolute path to the package to be installed
 * @param[out] id      The ID of the request to the package manager
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @see package_manager_request_uninstall()
 */
int package_manager_request_install(package_manager_request_h request,
                    const char *path, int *id);

/**
 * @internal
 * @brief Uninstalls the package with the given name.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/packagemanager.admin
 * @param[in]  request The request handle
 * @param[in]  name    The name of the package to be uninstalled
 * @param[out] id      The ID of the request to the package manager
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 */
int package_manager_request_uninstall(package_manager_request_h request,
                      const char *name, int *id);

/**
 * @internal
 * @brief Moves the package from SD card to the internal memory and vice versa.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/packagemanager.admin
 * @param[in] request   The request handle
 * @param[in] name      The name of the package to be moved
 * @param[in] move_type The move type [enum package_manager_move_type_e], [external to internal/internal to external]
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 */
int package_manager_request_move(package_manager_request_h request,
                    const char *name, package_manager_move_type_e move_type);


/**
 * @brief Called when the package is installed, uninstalled or updated, and the progress of the request to the package manager changes.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] type        The type of the package to be installed, uninstalled or updated
 * @param[in] package     The name of the package to be installed, uninstalled or updated
 * @param[in] event_type  The type of the request to the package manager
 * @param[in] event_state The current state of the request to the package manager
 * @param[in] progress    The progress for the request that is being processed by the package manager \n
 *                        The range of progress is from @c 0 to @c 100.
 * @param[in] error       The error code when the package manager failed to process the request
 * @param[in] user_data   The user data passed from package_manager_set_event_cb()
 *
 * @see package_manager_set_event_cb()
 * @see package_manager_unset_event_cb()
 */
typedef void (*package_manager_event_cb) (
            const char *type,
            const char *package,
            package_manager_event_type_e event_type,
            package_manager_event_state_e event_state,
            int progress,
            package_manager_error_e error,
            void *user_data);

/**
 * @brief Creates a package manager handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @remarks You must release @a manager using package_manager_destroy().
 *
 * @param[out] manager The package manager handle that is newly created on success
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          Internal I/O error
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @see package_manager_destroy()
 */
int package_manager_create(package_manager_h * manager);

/**
 * @brief Destroys the package manager handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] manager The package manager handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see package_manager_create()
 */
int package_manager_destroy(package_manager_h manager);

/**
 * @brief Sets the event status of the package when the package is installed, uninstalled or updated.
 *        You can combine multiple status using OR operation which you want to listen.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param [in] manager     The package manager handle
 * @param [in] status_type The status of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          Internal I/O error
 *
 * @see package_manager_status_type_e
 * @see package_manager_set_event_cb()
 */
int package_manager_set_event_status(package_manager_h manager, int status_type);

/**
 * @brief Registers a callback function to be invoked when the package is installed, uninstalled or updated.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @param[in] manager    The package manager handle
 * @param[in] callback   The callback function to be registered
 * @param[in] user_data  The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @post package_manager_event_cb() will be invoked.
 *
 * @see package_manager_set_event_status()
 * @see package_manager_event_cb()
 * @see package_manager_unset_event_cb()
 */
int package_manager_set_event_cb(package_manager_h manager,
                 package_manager_event_cb callback,
                 void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] manager The package manager handle
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see package_manager_event_cb()
 * @see package_manager_set_event_cb()
 */
int package_manager_unset_event_cb(package_manager_h manager);

/**
 * @brief Called to retrieve all packages.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] package_info The package information
 * @param[in] user_data    The user data passed from the foreach function
 *
 * @return  @c true to continue with the next iteration of the loop,
 *          otherwise @c false to break out of the loop
 *
 * @see package_manager_foreach_package_info()
 */
typedef bool (*package_manager_package_info_cb) (
            package_info_h package_info,
            void *user_data);

/**
 * @brief Retrieves all package information of installed packages.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @param[in] callback  The callback function to be invoked
 * @param[in] user_data The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @post This function invokes package_manager_package_info_cb() repeatedly for each package information.
 *
 * @see package_manager_package_info_cb()
 */
int package_manager_foreach_package_info(package_manager_package_info_cb callback,
                    void *user_data);

/**
 * @brief Gets the package ID for the given app ID.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @param[in]  app_id     The ID of the application
 * @param[out] package_id The ID of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 */
int package_manager_get_package_id_by_app_id(const char *app_id, char **package_id);

/**
 * @brief Gets the package information for the given package.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @remarks You must release @a package_info using package_info_destroy().
 *
 * @param[in]  package_id   The ID of the package
 * @param[out] package_info The package information for the given package ID
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Database error occurred
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 */
int package_manager_get_package_info(const char *package_id, package_info_h *package_info);


/**
 * @brief Compares whether two package certifications are matched.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in]  lhs_package_id The first package ID to compare
 * @param[in]  rhs_package_id The second package ID to compare
 * @param[out] compare_result @c 0 if the certification information are matched,
 *                            otherwise the compared result
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          Database error occurred
 */
int package_manager_compare_package_cert_info(const char *lhs_package_id, const char *rhs_package_id, package_manager_compare_result_type_e *compare_result);

/**
 * @brief Compares whether two app certifications are matched.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in]  lhs_app_id     The first app ID to compare
 * @param[in]  rhs_app_id     The second app ID to compare
 * @param[out] compare_result @c 0 if the certification information are matched,
 *                            otherwise the compared result
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          Database error occurred
 */
 int package_manager_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, package_manager_compare_result_type_e *compare_result);

/**
 * @brief Checks whether the package is preloaded by @a app_id.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @param[in]  app_id   The ID of the application
 * @param[out] preload  The preload info of the package
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 */
int package_manager_is_preload_package_by_app_id(const char *app_id, bool *preload);

/**
 * @brief Gets the package permission type by @a app_id.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 * @param[in]  app_id          The ID of the application
 * @param[out] permission_type The package permission type
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 */
int package_manager_get_permission_type(const char *app_id, package_manager_permission_type_e *permission_type);

/**
 * @internal
 * @brief  Clears the application's internal and external cache directory.
 * @details All files stored in the cache directory of the application specified with the
 *          package ID are removed.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/packagemanager.admin
 *
 * @param[in] package_id  The package ID
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   No such package
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 * @retval #PACKAGE_MANAGER_ERROR_SYSTEM_ERROR      Severe system error
 */
int package_manager_clear_cache_dir(const char *package_id);

/**
 * @internal
 * @brief  Clears all applications' internal and external cache directory.
 * @details All files stored in the cache directory of each application are removed.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/packagemanager.admin
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   No such package
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 * @retval #PACKAGE_MANAGER_ERROR_SYSTEM_ERROR      Severe system error
 */
int package_manager_clear_all_cache_dir(void);

/**
 * @internal
 * @brief  The structure type for data structure for the package size information.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef struct package_size_info
{
    long long data_size;            /**< The size of files in the application's internal data directory */
    long long cache_size;           /**< The size of files in the application's internal cache directory */
    long long app_size;             /**< The size of files in the application's internal bin, lib, and
                                         res directories */
    long long external_data_size;   /**< The size of files in the application's external data directory */
    long long external_cache_size;  /**< The size of files in the application's external cache directory */
    long long external_app_size;    /**< The size of files in the application's res directory */
} package_size_info_t;

/**
 * @internal
 * @brief  Called when the package size information is obtained.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in]  package_id  The package ID
 * @param[in]  size_info   The pointer to the structure including the package size information
 * @param[in]  user_data   The user data to be passed to the callback function
 */
typedef void (*package_manager_size_info_receive_cb)(const char *package_id, const package_size_info_t *size_info, void *user_data);

/**
 * @internal
 * @brief  Called when the total package size information is obtained.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in]  size_info  The pointer to the structure including the package size information
 * @param[in]  user_data  The user data to be passed to the callback function
 */
typedef void (*package_manager_total_size_info_receive_cb)(const package_size_info_t *size_info, void *user_data);

/**
 * @internal
 * @brief  Gets the package size information.
 * @details The package size info is asynchronously obtained by the callback function.
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in]  package_id  The package ID
 * @param[in]  callback    The asynchronous callback function to get the package size information
 * @param[in]  user_data   The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   No such package
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permision denied
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 * @retval #PACKAGE_MANAGER_ERROR_SYSTEM_ERROR      Severe system error
 */
int package_manager_get_package_size_info(const char *package_id, package_manager_size_info_receive_cb callback, void *user_data);

/**
 * @internal
 * @brief  Gets the total package size information.
 * @details The total package size info is asynchronously obtained by the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 *
 * @param [in]	callback	The asynchronous callback function to get the total package size information
 * @param [in]	user_data	The user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE              Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE   No such package
 * @retval #PACKAGE_MANAGER_ERROR_PERMISSION_DENIED Permission denied
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR          I/O error
 * @retval #PACKAGE_MANAGER_ERROR_SYSTEM_ERROR      Severe system error
 */
int package_manager_get_total_package_size_info(package_manager_total_size_info_receive_cb callback, void *user_data);

/**
 * @brief Creates the package information filter handle from db.
 * @details All filter properties will be ANDed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 *
 * @param[out] handle Pointer to the package info filter handle.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR I/O error
 * @post package_manager_filter_destroy()
 * @see package_manager_filter_add_bool()
 * @see package_manager_filter_foreach_pkginfo()
 */
int package_manager_filter_create(package_manager_filter_h *handle);

/**
 * @brief This API destroys the package information filter handle freeing up all the resources
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] handle Pointer to the package info filter handle.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR I/O error
 * @pre package_manager_filter_create()
 * @see package_manager_filter_count()
 * @see package_manager_filter_foreach_package_info()
 */
int package_manager_filter_destroy(package_manager_filter_h handle);

/**
 * @brief This API adds a boolean filter property to the filter handle
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 *
 * @param[in] handle Pointer to the package info filter handle.
 * @param[in] property boolean property name.
 * @param[in] value value corresponding to the property.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR I/O error
 * @pre package_manager_filter_create()
 * @post package_manager_filter_destroy()
 * @see package_manager_filter_count()
 * @see package_manager_filter_foreach_package_info()
 */
int package_manager_filter_add_bool(package_manager_filter_h handle,
		const char *property, const bool value);

/**
 * @brief This API counts the package that satisfy the filter conditions
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 *
 * @param[in] handle Pointer to the package info filter handle.
 * @param[out] count Pointer to store the count value.
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR I/O error
 * @pre package_manager_filter_create()
 * @post package_manager_filter_destroy()
 * @see package_manager_filter_foreach_package_info()
 */
int package_manager_filter_count(package_manager_filter_h handle, int *count);

/**
 * @brief This API executes the user supplied callback function for each package that satisfy the filter conditions
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/packagemanager.info
 *
 * @param[in] handle Pointer to the package info filter handle.
 * @param[in] callback callback function.
 * @param[in] user_data user data to be passed to the callback function
 *
 * @return @c 0 on success,
 *         otherwise a negative error value
 *
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR I/O error
 * @pre package_manager_filter_create()
 * @post package_manager_filter_destroy()
 * @post This function invokes package_manager_package_info_cb() repeatedly for each package information.
 * @see package_manager_package_info_cb()
 * @see package_manager_filter_count()
 */
int package_manager_filter_foreach_package_info(package_manager_filter_h handle,
		package_manager_package_info_cb callback, void *user_data);

/**
* @}
*/

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_PACKAGE_MANAGER_H */

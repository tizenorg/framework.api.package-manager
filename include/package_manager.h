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
 * @addtogroup CAPI_PACKAGE_MANAGER_MODULE
 * @{
 */

/**
 * @brief Enumerations of error code
 */
typedef enum {
	PACKAGE_MANAGER_ERROR_NONE = TIZEN_ERROR_NONE, /**< Successful */
	PACKAGE_MANAGER_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, /**< Invalid parameter */
	PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, /**< Out of memory */
	PACKAGE_MANAGER_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR, /**< Internal I/O error */
	PACKAGE_MANAGER_ERROR_NO_SUCH_PACKAGE = TIZEN_ERROR_APPLICATION_CLASS | 0x71, /**< No such package */
} package_manager_error_e;

/**
 * @brief Enumeration of event type
 */
typedef enum {
	PACKAGE_MANAGER_EVENT_TYPE_INSTALL = 0,
	PACKAGE_MANAGER_EVENT_TYPE_UNINSTALL,
	PACKAGE_MANAGER_EVENT_TYPE_UPDATE,

	/* These enum will be deprecated. Use above enum instead. */
	PACAKGE_MANAGER_EVENT_TYPE_INSTALL = 0,
	PACAKGE_MANAGER_EVENT_TYPE_UNINSTALL,
	PACAKGE_MANAGER_EVENT_TYPE_UPDATE,
} package_manager_event_type_e;

/**
 * @brief Enumeration of event state
 */
typedef enum {
	PACKAGE_MANAGER_EVENT_STATE_STARTED = 0,
	PACKAGE_MANAGER_EVENT_STATE_PROCESSING,
	PACKAGE_MANAGER_EVENT_STATE_COMPLETED,
	PACKAGE_MANAGER_EVENT_STATE_FAILED,

	/* These enum will be deprecated. Use above enum instead. */
	PACAKGE_MANAGER_EVENT_STATE_STARTED = 0,
	PACAKGE_MANAGER_EVENT_STATE_PROCESSING,
	PACAKGE_MANAGER_EVENT_STATE_COMPLETED,
	PACAKGE_MANAGER_EVENT_STATE_FAILED,
} package_manager_event_state_e;

/**
 * @brief Enumeration of request mode
 */
typedef enum {
	PACKAGE_MANAGER_REQUEST_MODE_DEFAULT = 0,
	PACKAGE_MANAGER_REQUEST_MODE_QUIET,

	/* These enum will be deprecated. Use above enum instead. */
	PACAKGE_MANAGER_REQUEST_MODE_DEFAULT = 0,
	PACAKGE_MANAGER_REQUEST_MODE_QUIET,
} package_manager_request_mode_e;

/**
 * @brief Enumeration of move type
 */
typedef enum {
	PACKAGE_MANAGER_REQUEST_MOVE_TO_INTERNAL = 0,
	PACKAGE_MANAGER_REQUEST_MOVE_TO_EXTERNAL,

	/* These enum will be deprecated. Use above enum instead. */
	PACAKGE_MANAGER_REQUEST_MOVE_TO_INTERNAL = 0,
	PACAKGE_MANAGER_REQUEST_MOVE_TO_EXTERNAL,
} package_manager_move_type_e;

/**
 * @brief Enumeration of certification compare type
 */
typedef enum {
	PACKAGE_MANAGER_COMPARE_MATCH = 0,
	PACKAGE_MANAGER_COMPARE_MISMATCH,
	PACKAGE_MANAGER_COMPARE_LHS_NO_CERT,
	PACKAGE_MANAGER_COMPARE_RHS_NO_CERT,
	PACKAGE_MANAGER_COMPARE_BOTH_NO_CERT,

	/* These enum will be deprecated. Use above enum instead. */
	PACAKGE_MANAGER_COMPARE_MATCH = 0,
	PACAKGE_MANAGER_COMPARE_MISMATCH,
	PACAKGE_MANAGER_COMPARE_LHS_NO_CERT,
	PACAKGE_MANAGER_COMPARE_RHS_NO_CERT,
	PACAKGE_MANAGER_COMPARE_BOTH_NO_CERT,
} package_manager_compare_result_type_e;

/**
 * @brief Enumeration of permission type
 */
typedef enum {
	PACKAGE_MANAGER_PERMISSION_NORMAL = 0,
	PACKAGE_MANAGER_PERMISSION_SIGNATURE,
	PACKAGE_MANAGER_PERMISSION_PRIVILEGE,
} package_manager_permission_type_e;

/**
 * @brief Package manager handle
 */
typedef struct package_manager_s *package_manager_h;

/**
 * @brief Package manager request handle
 */
typedef struct package_manager_request_s *package_manager_request_h;

/**
 * @brief Called when the progress of the request to the package manager changes.
 *
 * @param [in] id The ID of the request to the package manager
 * @param [in] type The type of the package to install, uninstall or update
 * @param [in] package The name of the package to install, uninstall or update
 * @param [in] event_type The type of the request to the package manager
 * @param [in] event_state The current state of the request to the package manager
 * @param [in] progress The progress for the request that is being processed by the package manager \n
 * The range of progress is from 0 to 100.
 * @param [in] error The error code when the package manager failed to process the request
 * @param [in] user_data The user data passed from package_manager_request_set_event_cb()
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
 * @brief Creates a request handle to the package manager.
 *
 * @remarks The @a request must be released with package_manager_request_destroy() by you.
 * @param [out] request A request handle to be newly created on success
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Internal I/O error
 * @see package_manager_request_destroy()
 */
int package_manager_request_create(package_manager_request_h *request);

/**
 * @brief Destroys the request handle to the package manager.
 *
 * @param [in] request The request handle to the package manager
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @see package_manager_request_create()
 */
int package_manager_request_destroy(package_manager_request_h request);

/**
 * @brief Registers a callback function to be invoked when the progress of the request changes.
 *
 * @param [in] request The request handle
 * @param [in] callback The callback function to register
 * @param [in] user_data The user data to be passed to the callback function
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @post package_manager_request_event_cb() will be invoked.
 * @see package_manager_request_event_cb()
 * @see package_manager_request_unset_event_cb()
*/
int package_manager_request_set_event_cb(package_manager_request_h request,
					 package_manager_request_event_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 *
 * @param [in] request The request handle
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @see package_manager_request_event_cb()
 * @see package_manager_request_set_event_cb()
*/
int package_manager_request_unset_event_cb(package_manager_request_h request);

/**
 * @brief Sets the type of the package to install, uninstall or update.
 *
 * @param [in] request The request handle
 * @param [in] type The type of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
*/
int package_manager_request_set_type(package_manager_request_h request,
				     const char *type);

/**
 * @brief Sets the mode of the request.
 *
 * @param [in] request The request handle
 * @param [in] mode The mode of the request
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
*/
int package_manager_request_set_mode(package_manager_request_h request,
				     package_manager_request_mode_e mode);

/**
 * @brief Installs the package which is located at the given path.
 *
 * @param [in] request The request handle
 * @param [in] path The absolute path to the package to install
 * @param [out] id The ID of the request to the package manager
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @see package_manager_request_uninstall()
*/
int package_manager_request_install(package_manager_request_h request,
				    const char *path, int *id);

/**
 * @brief Uninstalls the package with the given name
 *
 * @param [in] request The request handle
 * @param [in] name The name of the package to uninstall
 * @param [out] id The ID of the request to the package manager
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
*/
int package_manager_request_uninstall(package_manager_request_h request,
				      const char *name, int *id);

/**
 * @brief moves the package from sd card to internal memory and vice versa..
 *
 * @param [in] request The request handle
 * @param [in] name The name of the package to move
 * @param [in] move_type move type[enum package_manager_move_type_e], [external to internal/internal to external]
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
*/
int package_manager_request_move(package_manager_request_h request,
				    const char *name, package_manager_move_type_e move_type);


/**
 * @brief Called when the package is installed, uninstalled or updated, and the progress of the request to the package manager changes.
 *
 * @param [in] type The type of the package to install, uninstall or update
 * @param [in] package The name of the package to install, uninstall or update
 * @param [in] event_type The type of the request to the package manager
 * @param [in] event_state The current state of the request to the package manager
 * @param [in] progress The progress for the request that is being processed by the package manager \n
 * The range of progress is from 0 to 100.
 * @param [in] error The error code when the package manager failed to process the request
 * @param [in] user_data The user data passed from package_manager_set_event_cb()
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
 *
 * @remarks The @a manager must be released with package_manager_destroy() by you
 * @param [out] manager A package manager handle to be newly created on success
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Internal I/O error
 * @see package_manager_destroy()
 */
int package_manager_create(package_manager_h * manager);

/**
 * @brief Destroys the package manager handle.
 *
 * @param [in] manager The package manager handle
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @see package_manager_create()
 */
int package_manager_destroy(package_manager_h manager);

/**
 * @brief Set the event of status of package when the package is installed, uninstalled or updated.
 *
 * @param [in] manager The package manager handle
 * @param [in] status_type The status of package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Internal I/O error
 */
int package_manager_set_event_status(package_manager_h manager, int status_type);

/**
 * @brief Registers a callback function to be invoked when the package is installed, uninstalled or updated.
 *
 * @param [in] manager The package manager handle
 * @param [in] callback The callback function to register
 * @param [in] user_data The user data to be passed to the callback function
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @post package_manager_event_cb() will be invoked.
 * @see package_manager_event_cb()
 * @see package_manager_unset_event_cb()
*/
int package_manager_set_event_cb(package_manager_h manager,
				 package_manager_event_cb callback,
				 void *user_data);

/**
 * @brief Unregisters the callback function.
 *
 * @param [in] manager The package manager handle
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @see package_manager_event_cb()
 * @see package_manager_set_event_cb()
*/
int package_manager_unset_event_cb(package_manager_h manager);


/**
 * @brief Retrieves all packages
 * @param[in] package_info The package information
 * @param[in] user_data The user data passed from the foreach function
 * @return @c true to continue with the next iteration of the loop, \n @c false to break out of the loop.
 * @see package_manager_foreach_package_info()
 */
typedef bool (*package_manager_package_info_cb) (
			package_info_h package_info,
			void *user_data);


/**
 * @brief Retrieves all package information of installed packages
 * @param [in] callback The callback function to invoke
 * @param [in] user_data The user data to be passed to the callback function
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @post	This function invokes package_manager_package_info_cb() repeatedly for each package information.
 * @see package_manager_package_info_cb()
 */
int package_manager_foreach_package_info(package_manager_package_info_cb callback,
					void *user_data);


/**
 * @brief Gets the package_id for the given app_id
 * @param [in] app_id The ID of the application
 * @param [out] package_id The ID of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 */
int package_manager_get_package_id_by_app_id(const char *app_id, char **package_id);


/**
 * @brief Gets the package information for the given package
 * @remarks @a package_info must be released with package_info_destroy() by you.
 * @param [in] package_id The ID of the package
 * @param [out] package_info The package information for the given package ID
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Database error occurred
 */
int package_manager_get_package_info(const char *package_id, package_info_h *package_info);


/**
 * @brief compare whether two package certification are matched.
 * @param [in] lhs	The first package ID to compare
 * @param [in] rhs	The second package ID to compare
 * @param [out] compare_result 0 if the certification information are matched, otherwise returns compared result
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Database error occurred
 */
int package_manager_compare_package_cert_info(const char *lhs_package_id, const char *rhs_package_id, package_manager_compare_result_type_e *compare_result);

/**
 * @brief compare whether two app certification are matched.
 * @param [in] lhs	The first app ID to compare
 * @param [in] rhs	The second app ID to compare
 * @param [out] compare_result 0 if the certification information are matched, otherwise returns compared result
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR Database error occurred
 */
 int package_manager_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, package_manager_compare_result_type_e *compare_result);

/**
 * @brief Gets whether the package is preload or not by app_id
 * @param [in] app_id The ID of the application
 * @param [out] preload The preload info of the package
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_manager_is_preload_package_by_app_id(const char *app_id, bool *preload);

/**
 * @brief Gets the package  permission type by app_id
 * @param [in] app_id The ID of the application
 * @param [out] permission_type The package permission type
 * @return 0 on success, otherwise a negative error value.
 * @retval #PACKAGE_MANAGER_ERROR_NONE Successful
 * @retval #PACKAGE_MANAGER_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #PACKAGE_MANAGER_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #PACKAGE_MANAGER_ERROR_IO_ERROR IO error
 */
int package_manager_get_permission_type(const char *app_id, package_manager_permission_type_e *permission_type);

/**
* @}
*/

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_PACKAGE_MANAGER_H */

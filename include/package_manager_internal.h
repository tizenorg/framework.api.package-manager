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


#ifndef __TIZEN_APPFW_PACKAGE_MANAGER_INTERNAL_H__
#define __TIZEN_APPFW_PACKAGE_MANAGER_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

int package_manager_error(package_manager_error_e error, const char *function, const char *description);

int package_manager_info_check_privilege();
int package_manager_admin_check_privilege();
#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_PACKAGE_MANAGER_INTERNAL_H__ */

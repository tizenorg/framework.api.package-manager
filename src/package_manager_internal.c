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

#include <package_manager.h>
#include <package_manager_internal.h>
#include <dlog.h>

#include <sys/smack.h>
#include <sys/types.h>
#include <fcntl.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_PACKAGE_MANAGER"

#define _LOGE(fmt, arg...) LOGE(fmt,##arg)
#define _LOGD(fmt, arg...) LOGD(fmt, ##arg)

int check_privilege(privilege_type type)
{
	int fd = 0;
	int ret = 0;
	char subject_label[SMACK_LABEL_LEN + 1] = "";

	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd < 0) {
		_LOGE("open [%d] failed!", errno);
		return PACKAGE_MANAGER_ERROR_IO_ERROR;
	}

	ret = read(fd, subject_label, SMACK_LABEL_LEN);
	if (ret < 0) {
		_LOGE("read [%d] failed!", errno);
		close(fd);
		return PACKAGE_MANAGER_ERROR_IO_ERROR;
	}

	close(fd);

	_LOGD("subject_label : %s", subject_label);

	if (type == PRIVILEGE_PACKAGE_MANAGER_INFO) {
		ret = smack_have_access(subject_label, "pkgmgr::info", "r");
		if (ret == -1) {
			_LOGE("smack_have_access() fail");
			return PACKAGE_MANAGER_ERROR_IO_ERROR;
		} else if (ret == 0) {
			_LOGD("permission denied");
			return PACKAGE_MANAGER_ERROR_PERMISSION_DENIED;
		}

		ret = smack_have_access(subject_label, "pkgmgr::db", "rlx");
		if (ret == -1) {
			_LOGE("smack_have_access() fail");
			return PACKAGE_MANAGER_ERROR_IO_ERROR;
		} else if (ret == 0) {
			_LOGD("permission denied");
			return PACKAGE_MANAGER_ERROR_PERMISSION_DENIED;
		}

		ret = smack_have_access(subject_label, "ail::db", "rlx");
		if (ret == 1) {
			_LOGD("permission allowed");
			return PACKAGE_MANAGER_ERROR_NONE;
		} else if (ret == -1) {
			_LOGE("smack_have_access() fail");
			return PACKAGE_MANAGER_ERROR_IO_ERROR;
		} else if (ret == 0) {
			_LOGD("permission denied");
			return PACKAGE_MANAGER_ERROR_PERMISSION_DENIED;
		}
	} else if (type == PRIVILEGE_PACKAGE_MANAGER_ADMIN) {
		ret = smack_have_access(subject_label, "pkgmgr::svc", "rwx");
		if (ret == 1) {
			_LOGD("permission allowed");
			return PACKAGE_MANAGER_ERROR_NONE;
		} else if (ret == -1) {
			_LOGE("smack_have_access() fail");
			return PACKAGE_MANAGER_ERROR_IO_ERROR;
		} else if (ret == 0) {
			_LOGD("permission denied");
			return PACKAGE_MANAGER_ERROR_PERMISSION_DENIED;
		}
	}

	return PACKAGE_MANAGER_ERROR_IO_ERROR;
}

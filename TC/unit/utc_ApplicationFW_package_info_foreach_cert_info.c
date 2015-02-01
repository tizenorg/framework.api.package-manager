/*
 *  capi-package-manager
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <tet_api.h>
#include <package_manager.h>

static void startup(void);
static void cleanup(void);

void (*tet_startup) (void) = startup;
void (*tet_cleanup) (void) = cleanup;

static void utc_ApplicationFW_package_info_foreach_cert_info_func_01(void);
static void utc_ApplicationFW_package_info_foreach_cert_info_func_02(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{utc_ApplicationFW_package_info_foreach_cert_info_func_01, POSITIVE_TC_IDX},
	{utc_ApplicationFW_package_info_foreach_cert_info_func_02, NEGATIVE_TC_IDX},
	{NULL, 0},
};

static void startup(void)
{
}

static void cleanup(void)
{
}
static void info_cb(package_info_app_component_type_e comp_type, const char *app_id, void *user_data)
{
	return 0;
}

/**
 * @brief Positive test case of package_info_foreach_cert_info()
 */
static void utc_ApplicationFW_package_info_foreach_cert_info_func_01(void)
{
	int ret = 0;
	int id;
	char *pkgid = "com.samsung.email";
	package_info_h package_info;
	package_info_h clone_info;

	package_info_create(pkgid, &package_info);

	ret = package_info_foreach_cert_info(package_info, info_cb, NULL);
	if (ret != 0) {
		tet_infoline
			("tc() failed in positive test case");
		tet_result(TET_FAIL);
		return;
	}
	package_info_destroy(package_info);

	tet_result(TET_PASS);
}


/**
 * @brief Negative test case of package_info_foreach_cert_info()
 */
static void utc_ApplicationFW_package_info_foreach_cert_info_func_02(void)
{
	int ret = 0;
	int id;
	package_info_h package_info;

	ret = package_info_foreach_cert_info(package_info, info_cb, NULL);
	if (ret != 0) {
		tet_infoline
		    ("tc() failed in positive test case");
		tet_result(TET_FAIL);
		return;
	}

	tet_result(TET_PASS);
}

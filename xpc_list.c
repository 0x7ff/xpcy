#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>

#define XPC_CACHE_PATH "/System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib"

extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

static void
print_sandbox_xpc(uint8_t *buf, size_t size) {
	CFDataRef cache_data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, buf, (CFIndex)size, kCFAllocatorNull);
	if(cache_data) {
		CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, cache_data, kCFPropertyListMutableContainersAndLeaves, NULL, NULL);
		CFRelease(cache_data);
		if(plist) {
			CFDictionaryRef launchdaemons = CFDictionaryGetValue(plist, CFSTR("LaunchDaemons"));
			CFIndex launchdaemons_cnt = CFDictionaryGetCount(launchdaemons), i;
			const void **launchdaemons_values = malloc(sizeof(void *) * (size_t)launchdaemons_cnt);
			if(launchdaemons_values) {
				CFDictionaryGetKeysAndValues(launchdaemons, NULL, launchdaemons_values);
				for(i = 0; i < launchdaemons_cnt; ++i) {
					CFDictionaryRef mach_services = CFDictionaryGetValue(launchdaemons_values[i], CFSTR("MachServices"));
					if(mach_services) {
						CFIndex mach_services_cnt = CFDictionaryGetCount(mach_services), j;
						const void **mach_services_keys = malloc(sizeof(void *) * (size_t)mach_services_cnt);
						if(mach_services_keys) {
							CFDictionaryGetKeysAndValues(mach_services, mach_services_keys, NULL);
							for(j = 0; j < mach_services_cnt; ++j) {
								const char *service = CFStringGetCStringPtr(mach_services_keys[j], kCFStringEncodingMacRoman);
								if(service) {
									mach_port_t sp = MACH_PORT_NULL;
									if(!bootstrap_look_up(bootstrap_port, service, &sp) && MACH_PORT_VALID(sp)) {
										CFStringRef program;
										const char *program_c;
										mach_port_deallocate(mach_task_self_, sp);
										if((program = CFDictionaryGetValue(launchdaemons_values[i], CFSTR("Program")))) {
											if((program_c = CFStringGetCStringPtr(program, kCFStringEncodingMacRoman))) {
												printf("Path: %s, ", program_c);
											}
										} else {
											CFArrayRef program_arguments = CFDictionaryGetValue(launchdaemons_values[i], CFSTR("ProgramArguments"));
											if((program = CFArrayGetValueAtIndex(program_arguments, 0))) {
												if((program_c = CFStringGetCStringPtr(program, kCFStringEncodingMacRoman))) {
													printf("Path: %s, ", program_c);
												}
											}
										}
										printf("service: %s\n", service);
									}
								}
							}
							free(mach_services_keys);
						}
					}
				}
				free(launchdaemons_values);
			}
			CFRelease(plist);
		}
	}
}

int
main(void)
{
	void *handle = dlopen(XPC_CACHE_PATH, RTLD_NOW);
	if(handle) {
		void *xpcd_cache = dlsym(handle, "__xpcd_cache");
		if(xpcd_cache) {
			Dl_info info;
			if(dladdr(xpcd_cache, &info)) {
				size_t size = 0;
				uint8_t *data = getsectiondata(info.dli_fbase, "__TEXT", "__xpcd_cache", &size);
				if(data) {
					print_sandbox_xpc(data, size);
				}
			}
		}
	}
}

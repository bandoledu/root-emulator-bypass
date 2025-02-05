setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Starting SSL Bypass Suite");

        const bypassStatus = {
            ssl: false,
            root: false,
        };

        const ROOT_FILES = [
           "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/failsafe/su",
            "/system/bin/su",
            "/su/bin/su",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/sd/xbin/su",
            "/system/xbin/busybox",
            "/system/xbin/daemonsu",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/app/Kinguser.apk",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple",
            "/init.magisk.rc",
            "/system/xbin/ku.sud",
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/data/adb/ksu.apk",
            "/data/adb/ksud.apk",
            "/data/adb/magisk.apk",
            "/data/adb/magisk_simple.apk",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
        ];

        const ROOT_PACKAGES = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com"
        ];

        const ROOT_BINARIES = new Set([
            "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk",
            "SuperSu.apk", "magisk", "magisk64", "magiskhide", "magiskboot"
        ]);

        const ROOT_PROPERTIES = new Map([
            ["ro.build.selinux", "1"],
            ["ro.debuggable", "0"],
            ["service.adb.root", "0"],
            ["ro.secure", "1"],
            ["ro.build.tags", "release-keys"],
            ["ro.build.type", "user"]
        ]);

        const SENSITIVE_PROPS = new Set([
            "ro.secure",
            "ro.debuggable",
            "ro.build.fingerprint",
            "service.adb.root"
        ]);

        const JavaClasses = {
            SSLContext: Java.use("javax.net.ssl.SSLContext"),
            Runtime: Java.use("java.lang.Runtime"),
            File: Java.use("java.io.File"),
            PackageManager: Java.use("android.app.ApplicationPackageManager"),
            ProcessBuilder: Java.use("java.lang.ProcessBuilder")
        };

        const LOG_LEVEL = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3
        };

        const CURRENT_LOG_LEVEL = LOG_LEVEL.INFO;

        const CONFIG = {
            enableSSLBypass: true,
            enableRootBypass: true,
            enableDetailedLogs: false,
            blockAllRootCommands: true,
            allowedRootCommands: new Set(["getprop"]), // Whitelist certain commands
        };

        function log(level, message, error) {
            if (level >= CURRENT_LOG_LEVEL) {
                switch(level) {
                    case LOG_LEVEL.DEBUG:
                        console.log("[D] " + message);
                        break;
                    case LOG_LEVEL.INFO:
                        console.log("[*] " + message);
                        break;
                    case LOG_LEVEL.WARN:
                        console.log("[!] " + message);
                        break;
                    case LOG_LEVEL.ERROR:
                        console.error("[E] " + message);
                        if (error) console.error(error.stack || error);
                        break;
                }
            }
        }

        function setupSSLBypass() {
            console.log("[+] Setting up SSL bypass...");
            try {
                bypassCertificateValidation();
                bypassOkHttp();
                bypassTrustKit();
                bypassWebViewClient();
                bypassCertificatePinning();
                
                bypassStatus.ssl = true;
                return true;
            } catch(e) {
                console.log("[-] SSL Bypass failed:", e);
                return false;
            }
        }

        function bypassCertificateValidation() {
            try {
                const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                const CustomTrustManager = Java.registerClass({
                    name: "com.custom.TrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function() {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });

                const SSLContext_init = JavaClasses.SSLContext.init.overload(
                    "[Ljavax.net.ssl.KeyManager;", 
                    "[Ljavax.net.ssl.TrustManager;", 
                    "java.security.SecureRandom"
                );

                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    SSLContext_init.call(this, keyManager, [CustomTrustManager.$new()], secureRandom);
                };
            } catch(e) {
                console.log("[-] Certificate validation bypass failed");
            }
        }

        function bypassOkHttp() {
            try {
                const CertificatePinner = Java.use("okhttp3.CertificatePinner");
                
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
                    return;
                };

                CertificatePinner.check$okhttp.implementation = function(hostname, certificates) {
                    return;
                };
            } catch(e) {
                console.log("[-] OkHttp bypass failed:", e);
            }
        }

        function bypassTrustKit() {
            console.log("[*] Setting up TrustKit bypass...");
            let bypassCount = 0;

            // Helper function to handle TrustKit class hooks
            const hookTrustKitClass = (className, methodName, overloadTypes = null) => {
                try {
                    const targetClass = Java.use(className);
                    const method = overloadTypes ? 
                        targetClass[methodName].overload(...overloadTypes) :
                        targetClass[methodName];

                    method.implementation = function(...args) {
                        const hostname = args[0] || "unknown";
                        console.log(`[+] Bypassing ${className}.${methodName} for: ${hostname}`);
                        return methodName.includes("verify") ? true : undefined;
                    };
                    bypassCount++;
                    return true;
                } catch(e) {
                    // Class not found is expected if TrustKit isn't used
                    if (!e.toString().includes("ClassNotFoundException")) {
                        console.log(`[-] Failed to hook ${className}.${methodName}:`, e);
                    }
                    return false;
                }
            };

            // TrustKit hostname verifier bypasses
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                "verify", 
                ["java.lang.String", "javax.net.ssl.SSLSession"]
            );

            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                "verify",
                ["java.lang.String", "java.security.cert.X509Certificate"]
            );

            // TrustKit certificate pinning bypass
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
                "checkServerTrusted"
            );

            // Additional TrustKit bypasses
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.TrustKit",
                "initializeWithNetworkSecurityConfiguration"
            );

            hookTrustKitClass(
                "com.datatheorem.android.trustkit.reporting.BackgroundReporter",
                "reportCertificateError"
            );

            if (bypassCount > 0) {
                console.log(`[+] Successfully set up ${bypassCount} TrustKit bypasses`);
            } else {
                console.log("[*] TrustKit not found in app (this is normal)");
            }
        }

        function bypassWebViewClient() {
            try {
                const WebViewClient = Java.use("android.webkit.WebViewClient");
                
                WebViewClient.onReceivedSslError.overload(
                    "android.webkit.WebView",
                    "android.webkit.SslErrorHandler",
                    "android.net.http.SslError"
                ).implementation = function(webView, handler, error) {
                    handler.proceed();
                };
            } catch(e) {
                console.log("[-] WebViewClient bypass failed:", e);
            }
        }

        function bypassCertificatePinning() {
            try {
                const UnverifiedCertError = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
                UnverifiedCertError.$init.implementation = function(message) {
                    try {
                        const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                        const exceptionStack = stackTrace.findIndex(stack => 
                            stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                        );
                        
                        if (exceptionStack >= 0) {
                            const callingStack = stackTrace[exceptionStack + 1];
                            const className = callingStack.getClassName();
                            const methodName = callingStack.getMethodName();
                            
                            return this.$init("SSL verification bypassed");
                        }
                    } catch(e) {
                        console.log("[-] Stack trace analysis failed:", e);
                    }
                    
                    return this.$init(message);
                };
            } catch(e) {
                console.log("[-] Certificate pinning bypass failed:", e);
            }
        }

        function setupRootBypass() {
            console.log("[+] Initializing Enhanced Root Detection Bypass...");
            try {
                // Add this check for root packages
                const pm = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageManager();
                ROOT_PACKAGES.forEach(pkg => {
                    try {
                        pm.getPackageInfo(pkg, 0);
                        log(LOG_LEVEL.DEBUG, `Found root package: ${pkg}`);
                    } catch(e) {
                        // Package not found - good
                    }
                });

                bypassNativeFileOperations();
                bypassBuildProps();
                bypassShellCommands();
                bypassRuntimeExec();
                enhancedFileBypass();
                bypassSystemProperties();
                bypassProcessBuilder();
                bypassBufferedReader();
                bypassSecureHardware();
                
                bypassStatus.root = true;
                return true;
            } catch(e) {
                console.error("[!] Root Bypass Error:", e);
                return false;
            }
        }

        function bypassNativeFileOperations() {
            try {
                const fopen = Module.findExportByName("libc.so", "fopen");
                if (fopen) {
                    Interceptor.attach(fopen, {
                        onEnter(args) {
                            this.filePath = args[0].readUtf8String();
                        },
                        onLeave(retval) {
                            if (retval.toInt32() !== 0 && ROOT_FILES.some(path => this.filePath.includes(path))) {
                                retval.replace(ptr(0x0));
                            }
                        }
                    });
                }

                const access = Module.findExportByName("libc.so", "access");
                if (access) {
                    Interceptor.attach(access, {
                        onEnter(args) {
                            this.filePath = args[0].readUtf8String();
                        },
                        onLeave(retval) {
                            if (retval.toInt32() === 0 && ROOT_FILES.some(path => this.filePath.includes(path))) {
                                retval.replace(ptr(-1));
                            }
                        }
                    });
                }

                const sysPropGet = Module.findExportByName("libc.so", "__system_property_get");
                if (sysPropGet) {
                    Interceptor.attach(sysPropGet, {
                        onEnter(args) {
                            this.key = args[0].readCString();
                            this.ret = args[1];
                        },
                        onLeave(retval) {
                            if (SENSITIVE_PROPS.has(this.key)) {
                                const safeValue = this.key.includes("fingerprint") ? 
                                    "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys" : "0";
                                const ptr = Memory.allocUtf8String(safeValue);
                                Memory.copy(this.ret, ptr, safeValue.length + 1);
                            }
                        }
                    });
                }
            } catch (e) {
                console.log("[-] Native hooks partial failure:", e);
            }
        }

        function enhancedFileBypass() {
            try {
                const UnixFileSystem = Java.use("java.io.UnixFileSystem");
                UnixFileSystem.checkAccess.implementation = function(file, access) {
                    const filename = file.getAbsolutePath();
                    if (ROOT_FILES.some(path => filename.includes(path))) {
                        return false;
                    }
                    return this.checkAccess(file, access);
                };
            } catch (e) {
                console.log("[-] UnixFileSystem hook failed:", e);
            }
        }

        function bypassShellCommands() {
            try {
                const ProcessImpl = Java.use("java.lang.ProcessImpl");
                ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
                    const cmd = cmdarray[0].toString();
                    const arg = cmdarray.length > 1 ? cmdarray[1].toString() : "";
                    
                    // Add package check
                    if (cmd === "pm" && arg === "list" && cmdarray.length > 2) {
                        // Block package listing that might reveal root apps
                        if (ROOT_PACKAGES.some(pkg => cmdarray[2].toString().includes(pkg))) {
                            cmdarray[0] = Java.use("java.lang.String").$new("");
                        }
                    }
                    
                    if ((cmd === "mount") || 
                        (cmd === "getprop" && SENSITIVE_PROPS.has(arg)) ||
                        (cmd.includes("which") && arg === "su")) {
                        cmdarray[0] = Java.use("java.lang.String").$new("");
                    }
                    
                    return this.start.call(this, cmdarray, env, dir, redirects, redirectErrorStream);
                };
            } catch (e) {
                console.log("[-] Shell command hook failed:", e);
            }
        }

        function bypassRuntimeExec() {
            try {
                const Runtime = Java.use("java.lang.Runtime");
                
                function shouldBlockCommand(cmd) {
                    cmd = cmd.toLowerCase();
                    return ROOT_BINARIES.has(cmd) || 
                           ROOT_PACKAGES.some(pkg => cmd.includes(pkg.toLowerCase())) ||
                           ["getprop", "mount", "build.prop", "id", "sh", "su", "which"].some(
                               blocked => cmd.includes(blocked)
                           );
                }

                const execOverloads = [
                    ["[Ljava.lang.String;"],
                    ["java.lang.String"],
                    ["java.lang.String", "[Ljava.lang.String;"],
                    ["[Ljava.lang.String;", "[Ljava.lang.String;"],
                    ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File"],
                    ["java.lang.String", "[Ljava.lang.String;", "java.io.File"]
                ];

                execOverloads.forEach(overload => {
                    Runtime.exec.overload(...overload).implementation = function() {
                        let cmd = arguments[0];
                        if (Array.isArray(cmd)) {
                            cmd = cmd[0];
                        }
                        
                        if (shouldBlockCommand(cmd.toString())) {
                            return this.exec.call(this, "echo");
                        }
                        return this.exec.apply(this, arguments);
                    };
                });
            } catch(e) {
                console.log("[-] Runtime.exec hooks failed:", e);
            }
        }

        function bypassSystemProperties() {
            try {
                const SystemProperties = Java.use("android.os.SystemProperties");
                
                SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                    if (ROOT_PROPERTIES.has(key)) {
                        return ROOT_PROPERTIES.get(key);
                    }
                    if (key.includes("qemu") || key.includes("goldfish") || key.includes("sdk")) {
                        return "";
                    }
                    return this.get(key);
                };
            } catch(e) {
                console.log("[-] System properties hook failed:", e);
            }
        }

        function bypassBufferedReader() {
            try {
                Java.use("java.io.BufferedReader").readLine.overload("boolean").implementation = function() {
                    const text = this.readLine.overload("boolean").call(this);
                    if (text && text.indexOf("ro.build.tags=test-keys") > -1) {
                        return text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }
                    return text;
                };
            } catch(e) {
                console.log("[-] BufferedReader hook failed:", e);
            }
        }

        function bypassProcessBuilder() {
            try {
                const blockedCommands = new Set(["getprop", "mount", "build.prop", "id", "su"]);
                
                JavaClasses.ProcessBuilder.start.implementation = function() {
                    const cmd = this.command.call(this);
                    
                    const hasBlockedCmd = Array.from(cmd).some(c => 
                        blockedCommands.has(c.toString()) || 
                        Array.from(blockedCommands).some(blocked => c.toString().includes(blocked))
                    );

                    if (hasBlockedCmd) {
                        this.command.call(this, ["echo"]);
                        return this.start.call(this);
                    }

                    return this.start.call(this);
                };

                Java.perform(function() {
                    try {
                        if (Java.available) {
                            const loadedClasses = Java.enumerateLoadedClassesSync();
                            if (loadedClasses.includes("java.lang.ProcessManager")) {
                                const ProcessManager = Java.use("java.lang.ProcessManager");
                                bypassProcessManager();
                            }
                        }
                    } catch(e) {
                        console.log("[-] ProcessManager not available");
                    }
                });

            } catch(e) {
                console.log("[-] ProcessBuilder hook failed:", e);
            }
        }

        function bypassProcessManager() {
            if (!JavaClasses.ProcessManager) return;

            try {
                const variants = [
                    {
                        params: ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File", "boolean"],
                        method: "exec"
                    },
                    {
                        params: ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.lang.String", 
                                "java.io.FileDescriptor", "java.io.FileDescriptor", 
                                "java.io.FileDescriptor", "boolean"],
                        method: "exec"
                    }
                ];

                variants.forEach(variant => {
                    if (JavaClasses.ProcessManager[variant.method]) {
                        JavaClasses.ProcessManager[variant.method].overload(...variant.params)
                        .implementation = function() {
                            const cmd = arguments[0];
                            if (Array.isArray(cmd) && cmd.some(c => 
                                c.indexOf("getprop") !== -1 || 
                                c === "mount" || 
                                c.indexOf("build.prop") !== -1 || 
                                c === "id" || 
                                c === "su")) {
                                arguments[0] = ["echo"];
                            }
                            return this[variant.method].apply(this, arguments);
                        };
                    }
                });
            } catch(e) {
                console.log("[-] ProcessManager hooks failed:", e);
            }
        }

        function bypassSecureHardware() {
            Java.perform(function() {
                try {
                    if (Java.available) {
                        const loadedClasses = Java.enumerateLoadedClassesSync();
                        if (loadedClasses.includes("android.security.keystore.KeyInfo")) {
                            const KeyInfo = Java.use("android.security.keystore.KeyInfo");
                            KeyInfo.isInsideSecureHardware.implementation = function() {
                                return true;
                            };
                        }
                    }
                } catch(e) {
                    console.log("[-] SecureHardware hook not available");
                }
            });
        }

        function setupBypass() {
            try {
                const results = {};
                
                if (CONFIG.enableSSLBypass) {
                    results.ssl = setupSSLBypass();
                }
                
                if (CONFIG.enableRootBypass) {
                    results.root = setupRootBypass();
                }

                if (CONFIG.enableDetailedLogs) {
                    log(LOG_LEVEL.DEBUG, "Detailed bypass results:", results);
                }

                return results;
            } catch(e) {
                log(LOG_LEVEL.ERROR, "Bypass setup failed", e);
                return {};
            }
        }

        try {
            const results = setupBypass();

            // Add detailed error reporting
            Object.entries(results).forEach(([type, success]) => {
                if (!success) {
                    console.log(`[-] ${type.toUpperCase()} bypass failed`);
                }
            });

            console.log("\n[*] Status:", Object.entries(results)
                .map(([k, v]) => `${k}: ${v ? "✓" : "✗"}`)
                .join(", "));

        } catch(err) {
            console.error("[!] Critical Error:", err.stack || err);
            // Optionally try to recover or apply fallback bypasses
        }
    });
}, 0);
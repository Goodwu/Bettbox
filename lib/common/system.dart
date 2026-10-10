import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:ffi/ffi.dart';
import 'package:bett_box/common/common.dart';
import 'package:bett_box/common/helper_auth.dart';
import 'package:bett_box/enum/enum.dart';
import 'package:bett_box/helper/helper.dart';
import 'package:bett_box/plugins/app.dart';
import 'package:bett_box/state.dart';
import 'package:bett_box/widgets/input.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart';
import 'package:synchronized/synchronized.dart';

enum _SetcapResult {
  granted,
  notInstalled,
  xattrUnsupported,
  failed,
}

class System {
  static System? _instance;

  System._internal();

  factory System() {
    _instance ??= System._internal();
    return _instance!;
  }

  bool get isDesktop => isWindows || isMacOS || isLinux;

  bool get isWindows => Platform.isWindows;

  bool get isMacOS => Platform.isMacOS;

  bool get isAndroid => Platform.isAndroid;

  bool get isLinux => Platform.isLinux;

  Future<int> get version async {
    final deviceInfo = await DeviceInfoPlugin().deviceInfo;
    return switch (Platform.operatingSystem) {
      'macos' => (deviceInfo as MacOsDeviceInfo).majorVersion,
      'android' => (deviceInfo as AndroidDeviceInfo).version.sdkInt,
      'windows' => (deviceInfo as WindowsDeviceInfo).majorVersion,
      String() => 0,
    };
  }

  static String _shellEscape(String value) {
    return "'${value.replaceAll("'", "'\\''")}'";
  }

  static Future<bool> _isSetuidRootOwned(
    String corePath,
    String ownerPrefix,
  ) async {
    final macOS = system.isMacOS;
    final result = await Process.run('stat', [
      if (macOS) '-f' else '-c',
      if (macOS) '%Su:%Sg %Sp' else '%U:%G %A',
      corePath,
    ]);
    if (result.exitCode != 0) return false;
    final parts = result.stdout.toString().trim().split(' ');
    if (parts.length < 2) return false;
    return parts.first.startsWith(ownerPrefix) && parts.last.contains('s');
  }

  Future<bool> _hasCoreCapabilities() async {
    try {
      final result = await Process.run('getcap', [appPath.corePath]);
      return result.exitCode == 0 &&
          result.stdout.toString().contains('cap_net_admin');
    } catch (_) {
      return false;
    }
  }

  // Reconciles adjacent state before answering: on non-setuid Linux this
  // repairs the data dir and re-asserts the polkit rule, and may prompt.
  Future<bool> reconcilePrivileges() async {
    if (system.isWindows) {
      if (kDebugMode) return windows?.isUserAnAdmin ?? false;
      final result = await windows?.checkService();
      return result == WindowsHelperServiceStatus.running;
    }

    if (system.isMacOS) {
      return _isSetuidRootOwned(appPath.corePath, 'root:admin');
    }

    if (Platform.isLinux) {
      if (appPath.isAppImage) {
        await appPath.ensureAppImageCoreSynced();
      }
      // A setuid core needs neither the data-dir repair nor the polkit rule:
      // its Go-side permission guard reclaims ownership itself, and it calls
      // resolvectl as root, which polkit authorizes implicitly.
      if (await _isSetuidRootOwned(appPath.corePath, 'root:')) return true;
      await _repairForeignOwnedDataDir();
      await _ensurePolkitRule();
      return await _hasCoreCapabilities();
    }

    return true;
  }

  Future<AuthorizeCode> authorizeCore() async {
    if (system.isAndroid) return AuthorizeCode.none;

    if (await reconcilePrivileges()) return AuthorizeCode.none;

    if (system.isWindows) {
      if (kDebugMode) return AuthorizeCode.error;
      if (await windows?.isHelperHealthy() ?? false) return AuthorizeCode.none;
      final result = await windows?.registerService();
      return result == true ? AuthorizeCode.success : AuthorizeCode.error;
    }

    if (system.isMacOS) {
      var quarantineCleared = true;
      const quarantineAttr = 'com.apple.quarantine';
      final core = _shellEscape(appPath.corePath);

      final xattrCheck = await Process.run('/usr/bin/xattr', [
        '-p',
        quarantineAttr,
        appPath.corePath,
      ]);
      if (xattrCheck.exitCode == 0) {
        final removeResult = await Process.run('/usr/bin/xattr', [
          '-d',
          quarantineAttr,
          appPath.corePath,
        ]);
        if (removeResult.exitCode == 0) {
          commonPrint.log('Cleared quarantine attribute from BettboxCore');
        } else {
          quarantineCleared = false;
          commonPrint.warn(
            'Failed to clear quarantine attribute: ${removeResult.stderr}',
          );
        }
      }

      final shell = 'chown root:admin $core && chmod u+s $core';
      final result = await Process.run('osascript', [
        '-e',
        'do shell script "$shell" with administrator privileges',
      ]);

      if (result.exitCode != 0) {
        globalState.showNotifier(
          !quarantineCleared
              ? 'Failed to authorize BettboxCore. Try: xattr -dr com.apple.quarantine /Applications/Bettbox.app'
              : appLocalizations.tunEnableRequireAdmin,
        );
        return AuthorizeCode.error;
      }
      return AuthorizeCode.success;
    }

    if (Platform.isLinux) {
      if (appPath.isAppImage) {
        await appPath.ensureAppImageCoreSynced();
      }

      final setcap = await _trySetcap();
      if (setcap != _SetcapResult.granted) {
        _showSetuidFallback(setcap);
        if (!(await _runPrivileged(await _linuxSetuidScript)).ok) {
          return AuthorizeCode.error;
        }
      }

      return AuthorizeCode.success;
    }

    return AuthorizeCode.error;
  }

  Future<bool> _ensurePolkitRule() async {
    if (!Platform.isLinux) return false;
    if (await _hasPolkitRule) return true;

    final bundled = File(
      '${appPath.executableDirPath}/$_polkitRuleFileName',
    );
    if (!await bundled.exists()) return false;

    final staged = File(join(await appPath.homeDirPath, _polkitRuleFileName));
    await staged.writeAsString(await bundled.readAsString(), flush: true);

    final script =
        'install -Dm644 ${_shellEscape(staged.path)} $_polkitRuleSystemPath';

    final run = await _runPrivileged(script);
    await staged.delete();
    if (!run.ok) return false;
    return _hasPolkitRule;
  }

  static const _polkitRuleFileName = '99-bettbox.rules';

  static const _polkitRuleSystemPath =
      '/usr/share/polkit-1/rules.d/$_polkitRuleFileName';

  Future<_SetcapResult> _trySetcap() async {
    if (!await _hasSetcapBinary) return _SetcapResult.notInstalled;
    if (!_coreDirSupportsXattr) return _SetcapResult.xattrUnsupported;

    final run = await _runPrivileged(
      await _linuxSetcapScript,
      notifyOnFailure: false,
    );
    if (run.ok) return _SetcapResult.granted;

    commonPrint.log('setcap failed unexpectedly: ${run.stderr.trim()}');
    return _SetcapResult.failed;
  }

  void _showSetuidFallback(_SetcapResult result) {
    final message = switch (result) {
      _SetcapResult.notInstalled =>
        'setcap is not installed or not in the PATH, fallback to setuid',
      _SetcapResult.xattrUnsupported =>
        'xattr is not supported by the filesystem, fallback to setuid',
      _SetcapResult.failed =>
        'Could not grant file capabilities, fallback to setuid',
      _SetcapResult.granted => null,
    };
    if (message == null) return;
    commonPrint.log('Falling back to setuid: $result');
    globalState.showNotifier(message);
  }

  static Future<String> get _linuxSetcapScript async {
    final core = _shellEscape(appPath.corePath);
    const capabilities = 'cap_net_admin,cap_net_bind_service,cap_net_raw=+ep';

    return "setcap '$capabilities' $core && sync";
  }

  static Future<String> get _linuxSetuidScript async {
    final core = _shellEscape(appPath.corePath);

    return 'chown root:root $core && chmod u+s $core && sync';
  }

  static Future<bool> get _hasPolkitRule async =>
      File(_polkitRuleSystemPath).exists();

  static Future<int?> _currentUid() => _idField('-u');

  static Future<int?> _currentGid() => _idField('-g');

  static Future<bool> get _hasSetcapBinary async {
    try {
      final result = await Process.run('sh', ['-c', 'command -v setcap']);
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> get _hasForeignOwnedDataDir async {
    try {
      final result = await Process.run('sh', [
        '-c',
        'find "\$1" ! -user "\$(id -u)" -print -quit 2>/dev/null',
        'sh',
        await appPath.homeDirPath,
      ]);
      return result.exitCode == 0 && result.stdout.toString().trim().isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  Future<void> _repairForeignOwnedDataDir() async {
    if (!await _hasForeignOwnedDataDir) return;

    final uid = await _currentUid();
    final gid = await _currentGid();
    if (uid == null || gid == null) {
      commonPrint.log('Data dir repair skipped: cannot determine own uid/gid');
      return;
    }

    final dataDir = _shellEscape(await appPath.homeDirPath);
    final run = await _runPrivileged(
      'if [ -d $dataDir ]; then chown -R $uid:$gid $dataDir; fi',
      notifyOnFailure: false,
    );
    if (run.ok) {
      commonPrint.log('Repaired data dir entries owned by another user');
    } else {
      commonPrint.log('Data dir repair failed: ${run.stderr.trim()}');
    }
  }

  static bool get _coreDirSupportsXattr {
    final directory = dirname(appPath.corePath);
    try {
      final libc = DynamicLibrary.open('libc.so.6');
      final getxattr = libc.lookupFunction<
        IntPtr Function(IntPtr, IntPtr, IntPtr, IntPtr),
        int Function(int, int, int, int)
      >('getxattr');
      final errnoLocation = libc.lookupFunction<IntPtr Function(), int Function()>(
        '__errno_location',
      );

      final pathPtr = directory.toNativeUtf8();
      final namePtr = _xattrProbeName.toNativeUtf8();
      try {
        getxattr(pathPtr.address, namePtr.address, 0, 0);
        final errno = Pointer<Int32>.fromAddress(errnoLocation()).value;
        return errno != _eOpNotSupp && errno != _eNoSys;
      } finally {
        malloc.free(pathPtr);
        malloc.free(namePtr);
      }
    } catch (e) {
      commonPrint.log('xattr probe unavailable, assuming supported: $e');
      return true;
    }
  }

  static const _xattrProbeName = 'user.bettbox.xattr-probe';

  static const _eOpNotSupp = 95;

  static const _eNoSys = 38;

  static Future<int?> _idField(String flag) async {
    try {
      final result = await Process.run('id', [flag]);
      if (result.exitCode != 0) return null;
      return int.tryParse(result.stdout.toString().trim());
    } catch (_) {
      return null;
    }
  }

  Future<({bool ok, String stderr})> _runPrivileged(
    String script, {
    bool notifyOnFailure = true,
  }) async {
    try {
      final result = await Process.run('pkexec', ['sh', '-c', script]);
      if (result.exitCode == 0) return (ok: true, stderr: '');
      if (result.exitCode != 127) {
        if (notifyOnFailure) {
          globalState.showNotifier(appLocalizations.tunEnableRequireAdmin);
        }
        return (ok: false, stderr: result.stderr.toString());
      }
    } catch (e) {
      commonPrint.warn('pkexec failed: $e');
    }

    window?.show();
    final password = await globalState.showCommonDialog<String>(
      child: InputDialog(
        obscureText: true,
        title: appLocalizations.pleaseInputAdminPassword,
        value: '',
      ),
    );
    if (password == null || password.isEmpty) {
      if (notifyOnFailure) {
        globalState.showNotifier(appLocalizations.tunEnableRequireAdmin);
      }
      return (ok: false, stderr: '');
    }

    final result = await Process.run(Platform.environment['SHELL'] ?? 'bash', [
      '-c',
      'echo ${_shellEscape(password)} | sudo -S sh -c ${_shellEscape(script)}',
    ]);
    if (result.exitCode != 0 && notifyOnFailure) {
      globalState.showNotifier(appLocalizations.tunEnableRequireAdmin);
    }
    return (ok: result.exitCode == 0, stderr: result.stderr.toString());
  }

  Future<void> back() async {
    if (system.isAndroid) await app.moveTaskToBack();
    await window?.hide();
  }

  Future<void> exit() async {
    if (system.isAndroid) await SystemNavigator.pop();
    await window?.close();
  }

  Future<void> setProcessPriority(String processName, bool enable) async {
    if (!isWindows) return;

    if (processName == '${AppIdentity.mainExecutableName}.exe') {
      try {
        windows?.setCurrentProcessPriority(enable);
        return;
      } catch (e) {
        commonPrint.warn('Failed to set current process priority: $e');
      }
    }

    final result = await Process.run('wmic', [
      'process',
      'where',
      'name="$processName"',
      'call',
      'setpriority',
      enable ? 'above normal' : 'normal',
    ]);

    if (result.exitCode != 0) {
      throw Exception('Failed to set process priority: ${result.stderr}');
    }
  }
}

final system = System();

class Windows {
  static Windows? _instance;
  late DynamicLibrary _shell32;

  Windows._internal() {
    _shell32 = DynamicLibrary.open('shell32.dll');
  }

  factory Windows() {
    _instance ??= Windows._internal();
    return _instance!;
  }

  void setCurrentProcessPriority(bool enable) {
    final kernel32 = DynamicLibrary.open('kernel32.dll');

    final getCurrentProcess = kernel32
        .lookupFunction<IntPtr Function(), int Function()>('GetCurrentProcess');

    final setPriorityClass = kernel32
        .lookupFunction<
          Int32 Function(IntPtr hProcess, Int32 dwPriorityClass),
          int Function(int hProcess, int dwPriorityClass)
        >('SetPriorityClass');

    final setProcessInformation = kernel32
        .lookupFunction<
          Int32 Function(
            IntPtr hProcess,
            Int32 processInformationClass,
            Pointer<Void> processInformation,
            Uint32 processInformationSize,
          ),
          int Function(
            int hProcess,
            int processInformationClass,
            Pointer<Void> processInformation,
            int processInformationSize,
          )
        >('SetProcessInformation');

    final priorityClass = enable ? 0x00008000 : 0x00000020;

    final hProcess = getCurrentProcess();
    final result = setPriorityClass(hProcess, priorityClass);

    if (result == 0) {
      throw Exception('SetPriorityClass failed');
    }

    commonPrint.log(
      'Set current process priority to ${enable ? "above normal" : "normal"}',
    );

    if (enable) {
      final memoryPriorityInfo = calloc<Uint32>();
      try {
        memoryPriorityInfo.value = 5;
        final memoryResult = setProcessInformation(
          hProcess,
          0,
          memoryPriorityInfo.cast<Void>(),
          sizeOf<Uint32>(),
        );
        if (memoryResult == 0) {
          commonPrint.warn('Set current process memory priority failed');
        } else {
          commonPrint.log('Set current process memory priority to normal');
        }
      } finally {
        calloc.free(memoryPriorityInfo);
      }
    }
  }

  bool get isUserAnAdmin {
    final isUserAnAdmin = _shell32
        .lookupFunction<Int32 Function(), int Function()>('IsUserAnAdmin');
    return isUserAnAdmin() != 0;
  }

  bool runas(String command, String arguments, {bool showWindow = false}) {
    final commandPtr = command.toNativeUtf16();
    final argumentsPtr = arguments.toNativeUtf16();
    final operationPtr = 'runas'.toNativeUtf16();

    final shellExecute = _shell32
        .lookupFunction<
          Int32 Function(
            Pointer<Utf16> hwnd,
            Pointer<Utf16> lpOperation,
            Pointer<Utf16> lpFile,
            Pointer<Utf16> lpParameters,
            Pointer<Utf16> lpDirectory,
            Int32 nShowCmd,
          ),
          int Function(
            Pointer<Utf16> hwnd,
            Pointer<Utf16> lpOperation,
            Pointer<Utf16> lpFile,
            Pointer<Utf16> lpParameters,
            Pointer<Utf16> lpDirectory,
            int nShowCmd,
          )
        >('ShellExecuteW');

    // 0 = hide, 1 = show
    final result = shellExecute(
      nullptr,
      operationPtr,
      commandPtr,
      argumentsPtr,
      nullptr,
      showWindow ? 1 : 0,
    );

    calloc.free(commandPtr);
    calloc.free(argumentsPtr);
    calloc.free(operationPtr);

    commonPrint.log('windows runas: [command masked] resultCode:$result');

    return result > 32;
  }

  Future<WindowsHelperServiceStatus> checkService() async {
    await HelperAuthManager.ensureAuthKey();
    final result = await Process.run('sc', ['query', appHelperService]);
    if (result.exitCode != 0) return WindowsHelperServiceStatus.none;

    final output = result.stdout.toString();
    if (!output.contains('RUNNING')) return WindowsHelperServiceStatus.presence;

    return await _pingHelper()
        ? WindowsHelperServiceStatus.running
        : WindowsHelperServiceStatus.presence;
  }

  Future<bool>? _registerServiceInFlight;

  Future<bool> registerService() {
    return _registerServiceInFlight ??= _registerService().whenComplete(
      () => _registerServiceInFlight = null,
    );
  }

  Future<bool> _registerService() async {
    await HelperAuthManager.ensureAuthKey();
    if (await isHelperHealthy()) return true;

    if (!await _configureHelperService()) return false;

    return _waitForHelperHealthy();
  }

  Future<bool> isHelperHealthy() async {
    final result = await Process.run('sc', ['query', appHelperService]);
    if (result.exitCode != 0) return false;

    if (!result.stdout.toString().contains('RUNNING')) return false;

    return _pingHelper();
  }

  Future<bool> _pingHelper() async {
    final coreSHA256 = await globalState.getOrCalcCoreSHA256();
    if (coreSHA256 == null || coreSHA256.isEmpty) return false;
    return helperClient.ping(coreSHA256);
  }

  Future<bool> _configureHelperService() async {
    final authKey = HelperAuthManager.getAuthKey();
    if (authKey == null) return false;

    final serviceRegistryPath =
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\$appHelperService';

    final command = [
      '/c',
      'sc',
      'stop',
      appHelperService,
      '>nul',
      '2>&1',
      '&',
      'sc',
      'delete',
      appHelperService,
      '>nul',
      '2>&1',
      '&',
      'sc',
      'create',
      appHelperService,
      'binPath= "${appPath.helperPath}"',
      'start= ${AppIdentity.isDev ? 'demand' : 'auto'}',
      '&&',
      'reg',
      'add',
      '"$serviceRegistryPath"',
      '/v',
      'Environment',
      '/t',
      'REG_MULTI_SZ',
      '/d',
      '"HELPER_AUTH_KEY=$authKey\\0HELPER_SERVICE_NAME=$appHelperService\\0HELPER_PIPE_NAME=$helperPipeName"',
      '/f',
      '&&',
      'sc',
      'start',
      appHelperService,
    ].join(' ');

    return runas('cmd.exe', command);
  }

  Future<bool> _waitForHelperHealthy() async {
    for (var attempt = 0; attempt < 20; attempt++) {
      await Future.delayed(const Duration(milliseconds: 250));
      if (await isHelperHealthy()) return true;

      if (attempt > 0 && attempt % 4 == 0) {
        final check = await Process.run('sc', ['query', appHelperService]);
        final output = check.stdout.toString();
        if (output.contains('STOPPED')) {
          commonPrint.warn('Helper service stopped/failed, skipping wait');
          break;
        }
      }
    }

    return false;
  }

  Future<void> stopHelperService() async {
    await helperClient.stopCore();
    if (!AppIdentity.isDev) return;

    if (await helperClient.stopHelperService()) {
      return;
    }

    await Process.run('sc', ['stop', appHelperService]);
  }

  Future<bool> registerTask(String appName) async {
    final executablePath = Platform.resolvedExecutable;
    final workingDirectory = dirname(executablePath);

    final taskXml =
        '''
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>开机自动启动代理服务</Description>
    <URI>\\$appName</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>6</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"$executablePath"</Command>
      <WorkingDirectory>$workingDirectory</WorkingDirectory>
    </Exec>
  </Actions>
</Task>''';
    final taskPath = join(await appPath.tempPath, 'task.xml');
    await File(taskPath).create(recursive: true);
    await File(
      taskPath,
    ).writeAsBytes(taskXml.encodeUtf16LeWithBom, flush: true);
    final commandLine = [
      '/Create',
      '/TN',
      appName,
      '/XML',
      '%s',
      '/F',
    ].join(' ');
    return runas('schtasks', commandLine.replaceFirst('%s', taskPath));
  }

  Future<bool> unregisterTask(String appName) async {
    final commandLine = ['/Delete', '/TN', appName, '/F'].join(' ');
    return runas('schtasks', commandLine);
  }
}

final windows = system.isWindows ? Windows() : null;

class MacOS {
  static MacOS? _instance;
  static const _dnsBackupFileName = 'macos_system_dns_backup.json';
  static const _hijackDns = '223.5.5.5';
  final Lock _dnsLock = Lock();

  MacOS._internal();

  factory MacOS() {
    _instance ??= MacOS._internal();
    return _instance!;
  }

  Future<String?> get defaultServiceName async {
    final result = await Process.run('route', ['-n', 'get', 'default']);
    final output = result.stdout.toString();
    final deviceLine = output
        .split('\n')
        .firstWhere((s) => s.contains('interface:'), orElse: () => '');
    final parts = deviceLine.trim().split(' ');
    if (parts.length != 2) return null;

    final device = parts[1];
    final serviceResult = await Process.run('networksetup', [
      '-listnetworkserviceorder',
    ]);
    final serviceOutput = serviceResult.stdout.toString();
    final currentService = serviceOutput
        .split('\n\n')
        .firstWhere((s) => s.contains('Device: $device'), orElse: () => '');
    if (currentService.isEmpty) return null;

    final serviceNameLine = currentService
        .split('\n')
        .firstWhere(
          (line) => RegExp(r'^\(\d+\).*').hasMatch(line),
          orElse: () => '',
        );
    final match = RegExp(
      r'^\(\d+\)\s+(.+)$',
    ).firstMatch(serviceNameLine.trim());
    return match?.group(1)?.trim();
  }

  Future<List<String>?> get systemDns async {
    final deviceServiceName = await defaultServiceName;
    if (deviceServiceName == null) return null;
    return _getSystemDns(deviceServiceName);
  }

  Future<List<String>?> _getSystemDns(String serviceName) async {
    final result = await Process.run('networksetup', [
      '-getdnsservers',
      serviceName,
    ]);
    if (result.exitCode != 0) {
      commonPrint.warn(
        'Failed to get macOS system DNS: ${result.stderr.toString().trim()}',
      );
      return null;
    }
    final output = result.stdout.toString().trim();
    return output.startsWith("There aren't any DNS Servers set on")
        ? []
        : output.split('\n');
  }

  Future<void> updateDns(bool restore) {
    return _dnsLock.synchronized(() async {
      if (restore) {
        await _restoreDns();
      } else {
        await _setDns();
      }
    });
  }

  Future<void> _setDns() async {
    // Restore a previous managed value first so repeated enable operations never
    // overwrite the real system DNS backup with Bettbox's own hijack DNS.
    if (!await _restoreDns()) return;

    final serviceName = await defaultServiceName;
    if (serviceName == null) return;

    final currentDns = await _getSystemDns(serviceName);
    if (currentDns == null || currentDns.contains(_hijackDns)) return;

    final backup = jsonEncode({
      'serviceName': serviceName,
      'servers': currentDns,
    });
    try {
      final backupFile = await _dnsBackupFile;
      await backupFile.parent.create(recursive: true);
      final temporaryFile = File('${backupFile.path}.tmp');
      await temporaryFile.writeAsString(backup, flush: true);
      await temporaryFile.rename(backupFile.path);
    } catch (e) {
      commonPrint.warn('Failed to persist the original macOS system DNS: $e');
      return;
    }

    final result = await Process.run('networksetup', [
      '-setdnsservers',
      serviceName,
      ...currentDns,
      _hijackDns,
    ]);
    if (result.exitCode != 0) {
      commonPrint.warn(
        'Failed to set macOS system DNS: ${result.stderr.toString().trim()}',
      );
    }
  }

  Future<bool> _restoreDns() async {
    final backupFile = await _dnsBackupFile;
    if (!await backupFile.exists()) return true;

    try {
      final rawBackup = await backupFile.readAsString();
      final decodedBackup = jsonDecode(rawBackup);
      if (decodedBackup is! Map) {
        throw const FormatException('Invalid macOS system DNS backup');
      }
      final backup = Map<String, dynamic>.from(decodedBackup);
      final serviceName = backup['serviceName'] as String?;
      final servers = (backup['servers'] as List?)
          ?.whereType<String>()
          .toList();
      if (serviceName == null || serviceName.isEmpty || servers == null) {
        throw const FormatException('Invalid macOS system DNS backup');
      }

      final result = await Process.run('networksetup', [
        '-setdnsservers',
        serviceName,
        if (servers.isNotEmpty) ...servers,
        if (servers.isEmpty) 'Empty',
      ]);
      if (result.exitCode != 0) {
        commonPrint.warn(
          'Failed to restore macOS system DNS: '
          '${result.stderr.toString().trim()}',
        );
        return false;
      }
      await backupFile.delete();
      return true;
    } catch (e) {
      commonPrint.warn('Failed to read macOS system DNS backup: $e');
      return false;
    }
  }

  Future<File> get _dnsBackupFile async {
    return File(join(await appPath.homeDirPath, _dnsBackupFileName));
  }
}

final macOS = system.isMacOS ? MacOS() : null;

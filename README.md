# root-checker

This plugin is used to detect whether a given device is rooted or not

## Install

```bash
npm install root-checker
npx cap sync
```

## API

<docgen-index>

* [`checkRoot()`](#checkroot)
* [`isDeveloperModeEnable()`](#isdevelopermodeenable)
* [`isEmulatorPresent()`](#isemulatorpresent)
* [`getCpuArchitecture()`](#getcpuarchitecture)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### checkRoot()

```typescript
checkRoot() => Promise<{ isRooted: boolean; }>
```

Get information about device root status

**Returns:** <code>Promise&lt;{ isRooted: boolean; }&gt;</code>

**Since:** 1.0.0

--------------------


### isDeveloperModeEnable()

```typescript
isDeveloperModeEnable() => Promise<{ isEnabled: boolean; }>
```

**Returns:** <code>Promise&lt;{ isEnabled: boolean; }&gt;</code>

--------------------


### isEmulatorPresent()

```typescript
isEmulatorPresent() => Promise<{ isEmulator: boolean; }>
```

**Returns:** <code>Promise&lt;{ isEmulator: boolean; }&gt;</code>

--------------------


### getCpuArchitecture()

```typescript
getCpuArchitecture() => Promise<{ cpuArch: string; }>
```

**Returns:** <code>Promise&lt;{ cpuArch: string; }&gt;</code>

--------------------

</docgen-api>

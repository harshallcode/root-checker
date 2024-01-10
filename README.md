# root-checker

This plugin is used to detect whether a given device is rooted or not

## Install

```bash
npm install root-checker
npx cap sync
```

## API

<docgen-index>

* [`echo(...)`](#echo)
* [`checkRoot(...)`](#checkroot)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### echo(...)

```typescript
echo(options: { value: string; }) => Promise<{ value: string; }>
```

| Param         | Type                            |
| ------------- | ------------------------------- |
| **`options`** | <code>{ value: string; }</code> |

**Returns:** <code>Promise&lt;{ value: string; }&gt;</code>

--------------------


### checkRoot(...)

```typescript
checkRoot(options: { isRooted: boolean; }) => Promise<void>
```

| Param         | Type                                |
| ------------- | ----------------------------------- |
| **`options`** | <code>{ isRooted: boolean; }</code> |

--------------------

</docgen-api>

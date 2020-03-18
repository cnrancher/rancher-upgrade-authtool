# rancher-upgrade-authtool

## What is it?

`rancher-upgrade-authtool` is used for rancher principal upgrade when using LDAP/AD auth config before v2.3.3-ent.

As previous version, we use `DistinguishedNames` attribute as user identifier which will result in losing permission when user changes DN in LDAP/AD.

To fix this, we change to use unique ID attribute of user/group in LDAP/AD.

`rancher-upgrade-authtool` will help you to add new principal attribute to your history users when you upgrading pandaria with LDAP/AD Authentication.

> This step is requisite when you upgrading pandaria from v2.3.3-ent or previous version with LDAP/AD authentication config.

## How to use it?

### Prerequisite

> Please make sure you have done all necessary preparations before upgrading pandaria, such as backup etcd, etc.

- Upgrade pandaria to latest version, e.g. v2.3.6-ent
- If you are going to change LDAP/AD authentication config, please login to Rancher Web GUI using local user `admin`(DO NOT using LDAP/AD user to login)

### Running parameters

```
USAGE:
   authtool [global options] command [command options] [arguments...]

COMMANDS:
   upgrade, u  upgrade rancher user to new version
   rollback, r rollback rancher user to old version

GLOBAL OPTIONS:
   --dry-run           Enable dry run
   --kubeconfig value  kube config for accessing local k8s cluster of rancher
   --auth-type value   auth type: 0 - AD auth, 1 - openldap auth
   --log-file value    log file path for upgrade
```

### Start example

```
authtool --kubeconfig=<kube-config> --auth-type=0 --dry-run=true --log-file=<log-file-path> upgrade
```

> Please using `--dry-run=true` before running the command to make sure running result as expect.

### Result description

If the running result print multiple data in final step: Step 6. Manual check data, means you need to check some data manually.

Need to check data manually for several reasons as following:

- `DistinguishedName` of user has changed, user re-login to rancher before upgrade.
    * This will shown as deprecate user. Need to choose and remove one.
- User has removed from LDAP/AD server
    * User still remain in Rancher but has removed from LDAP/AD server. It's not big deal to remove or not.
- `DistinguishedName` of user has changed, but find multiple users using RDN attribute like `cn`, `uid`, etc. 
    * The upgrade tool can't determine the N.unique user using current DN, need to edit user principal with correct DN manually, and then re-run the tool.
# keycloak-ip-cidr-authenticator

This is forked from  https://github.com/lukaszbudnik/keycloak-ip-authenticator

### <span style="color:red"> Tested only for keycloak 20.0.3 version </span>

This is a simple Keycloak Java Authenticator that checks if the user is coming from a trusted network or not. If the
user is coming from a trusted network MFA step is skipped. If the user is coming from a non-trusted network MFA step is
forced.

The authenticator has to be used together with `Conditional OTP Form` component.

See the following Youtube video which explains how to deploy and configure it in Keycloak: https://youtu.be/u36QK9oyrtM.

## build your own OR deploy `keycloak-ip-authenticator.jar` into `/opt/keycloak/providers/` folder

To build the project execute the following command:

```bash
mvn package
```

## deploy

```bash
cp target/keycloak-ip-authenticator.jar /opt/keycloak/providers/
```

## run keyckloak 

Run keycloak on dev mode

```bash
start-dev
```

# Configuration

### IP Authenticator config

* add step `IP Authenticator` in your flow
* set alias name for excample `ip-whitelist`
* set CIDR for excample `192.168.1.0/24`

### Conditional OTP Form config
* set alias name for excample `ip-whitelist`
* set OTP control User Attribute `ip_based_otp_conditional`
* set Fallback OTP handling  `skip`
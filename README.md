# Cisco Running Config Validator
Parser for Cisco IOS config 

Uses a template to identify configuration items that should be checked and conditions that should be satisfied 

This idea is for automating the identification of bugs, misconfigurations and unsupported combinations of features, using information that can be found in show tech and command outputs that are gathered during a troubleshooting session. These inputs are:

	•	devices software
	•	platform
	•	configuration commands
	•	command outputs and debugs

This can be done using signatures for configuration files, debugs and command outputs. These can have a syntax that makes them easy to write by any engineer, without the need to know programming or how the script works.

To create a connection between switch platform+software, conditions and resulting messages returned to user, the database tables could be like:

HW+SW_VERSION - many to many - CONDITIONS - many-to-many - RESULTS( the commands + message (not supported etc))

Creating signatures for running config:

CLI configuration has a tree-like structure, consisting of commands and subcommands that have specific syntax. For example:
```python
aaa new-model
interface fa0/1
 dot1x pae authenticator
 authentication event no-response action authorize vlan 1
 /* "dot1x pae authenticator" can be seen as a subcommand of "interface fa0/1" and commands have variables, eg "authenticator", "fa0/1", "1". */
```
 
Using a syntax that defines commands, their variables and subcommands , one can define signatures for command combinations that are problematic when combined with certain platform/software version.

Example: if we use '_' for variables, [x|y|z] for lists of possible values, 'X','Y',etc for variables that should have the same value in config, '~' for negation, we can define conditions for problematic configurations as below:
```python
interface _
 authentication host-mode [multi-auth|multi-domain|multi-host]
 authentication event fail action authorize vlan _
! dot1x auth fail van not supported in certain modes
```

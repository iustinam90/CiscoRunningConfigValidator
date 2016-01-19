condition_db_entries=["""
interface X; authentication host-mode [multi-domain]
interface X; authentication event server dead action reinitialize vlan _
""",
"""
interface X; authentication host-mode [multi-auth]
interface X; authentication event no-response action authorize vlan _
""",
"""
interface X; authentication host-mode [multi-auth|multi-domain]
interface X; authentication event server dead action reinitialize vlan _
""",
"""
interface X; authentication host-mode [multi-auth|multi-domain|multi-host]
interface X; authentication event fail action authorize vlan _
""",
### the following one is checking if all cmds are present.( because it does not contain X or [] ) . describes how it should be. ! cmd means that command should not exist
# if we have interfaces configured for dot1x, then dot1x should be enabled globally, etc
"""
interface _; dot1x pae authenticator
dot1x system-auth-control
aaa new-model
radius-server attribute 8 include-in-access-req
radius-server vsa send accounting
radius-server vsa send authentication
""",
### the following one is checking if all cmds are present.( because it does not contain X or [] ) . describes how it should be. ! cmd means that command should not exist
"""
interface X; authentication port-control auto
~interface X; no switchport
"""
]


condition_db_entries=["""
route-map _ permit _; match ip address _; set ip next-hop _
"""]

# condition_db_entries=["""
# nat (_, _) source static X X destination static Y Y [~no-proxy-arp]
# """]


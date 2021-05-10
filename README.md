# trapper

### Overview
This repository is used to convert SNMP traps to Nagios service checks. Nagios has a value it calls a "service" that can be in an "up" state or a "down "state. Trapper takes SNMP traps and sets nagios services to up or down depending on what the trap was for.

### Technology
- Haskell
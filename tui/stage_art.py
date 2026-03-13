from __future__ import annotations

# Per-stage ASCII art displayed in the log pane when each stage starts.
# Rules: max 4 lines, ASCII-only (no emoji — SSH terminal safety).
STAGE_ART: dict[int, str] = {
    1: (
        "    )))  BLE SCAN  (((\n"
        "   ))) ) ~~~~~~~~ ( (((\n"
        "  ))) )) [DEVICE?] (( (((\n"
        " ~~~~~~~~~~~~~~~~~~~~~"
    ),
    2: (
        "  [A] --->>>--- [B]\n"
        "   \\  CONN INTEL  /\n"
        "    \\___________/\n"
        "  < probing services >"
    ),
    3: (
        "  [REAL] --> |MIRROR|\n"
        "  ========== CLONE ==\n"
        "  [FAKE] <-- |COPY  |\n"
        "  ~~~~ identity ~~~~"
    ),
    4: (
        "  ~~~/\\/\\/\\/~~~  JAM\n"
        "  -={ NOISE }=-\n"
        "  ~~~\\/\\/\\/~~~\n"
        "  !!! REACTIVE !!!"
    ),
    5: (
        "  [SVC]-[CHR]-[DSC]\n"
        "  |GATT ENUM SHELL |\n"
        "  [SVC]-[CHR]-[DSC]\n"
        "  =================="
    ),
    6: (
        "  [CENTRAL]\n"
        "      |  MITM PROXY\n"
        "   [PROXY] <-->\n"
        "      |  [PERIPH]"
    ),
    7: (
        "  >-[???]-[???]-[???]->\n"
        "  GATT FUZZER  @#$%!\n"
        "  >-[!!!]-[~~~]-[***]->\n"
        "  spray & observe"
    ),
    8: (
        "  [ TARGET ] <---+\n"
        "  PoC PROBE  -->-+\n"
        "  [evidence  log]\n"
        "  ==============="
    ),
    9: (
        "  >>--[PDU]-->> inject\n"
        "  |===========|\n"
        "  >>--[PDU]-->>\n"
        "  ~ raw packet ~"
    ),
    10: (
        "  [KBD]===>>===[RX]\n"
        "  Unifying/MouseJack\n"
        "  [MSE]===>>===[RX]\n"
        "  ^ ^ sniff/inject"
    ),
    11: (
        "  *-*-* ZigBee *-*-*\n"
        " / \\ MESH NETWORK / \\\n"
        "*---*---*---*---*---*\n"
        " \\_____802.15.4_____/"
    ),
    12: (
        "  |----2.4 GHz----|  \n"
        "  | PHY SPECTRUM  |\n"
        "  |/\\/\\/\\/\\/\\/\\/\\/|\n"
        "  |___sweep_scan__|"
    ),
    13: (
        "  [  KEY  ] SMP\n"
        "   \\     /\n"
        "    [LOCK] <-> pair\n"
        "  =================="
    ),
    14: (
        "  _|_|_ ESB SCAN _|_|_\n"
        "  ~burst~ ~burst~ ~burst~\n"
        "  |||  passive sniff  |||\n"
        "  ======================"
    ),
    15: (
        "  /|\\  LoRaWAN  /|\\\n"
        "   |  long range  |\n"
        "  ~~~  ~  ~  ~  ~~~\n"
        "  Class A/B/C ABP/OTAA"
    ),
    16: (
        "  [L2CAP][L2CAP][L2CAP]\n"
        "  |------ stack ------|\n"
        "  [ HCI ][ ATT ][ SMP]\n"
        "  ===== layer test ===="
    ),
    17: (
        "  ~~~~ sub-GHz ~~~~\n"
        "  |  433/868/915  |\n"
        "  |~/\\/\\/\\/\\/\\/\\~/|\n"
        "  | YardStickOne  |"
    ),
    18: (
        "  [PTX] --data--> [PRX]\n"
        "  [PRX] <--ack--- [PTX]\n"
        "  ESB PRX/PTX active\n"
        "  ===================="
    ),
    19: (
        "  ~~~ Unifying API ~~~\n"
        "  >>==[KBD inject]==>>\n"
        "  >>==[MSE move  ]==>>\n"
        "  Python snake active"
    ),
    20: (
        "  [C] ---x---> [P]\n"
        "       HIJACK!\n"
        "  [C] <======> [P]\n"
        "  InjectaBLE hook"
    ),
    21: (
        "  (( BR/EDR SCOUT ))\n"
        "  classic bluetooth\n"
        "  [PAGE][INQUIRY][SDP]\n"
        "  ===================="
    ),
    22: (
        "  [RC] ---RF4CE---> [TV]\n"
        "  ZigBee-RF4CE pairing\n"
        "  [   target node    ]\n"
        "  ====================="
    ),
    23: (
        "  #-#-# 802.15.4 #-#-#\n"
        "  | raw frame grid   |\n"
        "  #---#---#---#---#--#\n"
        "  channel scan / sniff"
    ),
}

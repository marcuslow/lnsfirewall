#!/usr/bin/env python3
"""
Technical details of how pfSense rule loading works
"""

def explain_pfsense_rule_loading():
    """Detailed technical explanation of pfSense rule loading"""
    
    print("🔧 TECHNICAL DETAILS: How pfSense Loads New Rules")
    print("=" * 80)
    
    print("\n📁 FILE SYSTEM STRUCTURE:")
    print("-" * 40)
    print("/cf/conf/config.xml          ← Main pfSense configuration")
    print("/cf/conf/config.xml.backup.* ← Automatic backups")
    print("/etc/rc.filter_configure     ← pfSense reload script")
    print("/tmp/rules.debug             ← Generated pf rules (debug)")
    print("/var/log/filter.log          ← Firewall activity log")
    
    print("\n🔄 STEP-BY-STEP TECHNICAL PROCESS:")
    print("-" * 40)
    
    print("\n1️⃣  RULE RECEPTION")
    print("   • Client receives WebSocket message with 'set_rules' command")
    print("   • Extracts rules_xml parameter containing new firewall rules")
    print("   • Rules are in pfSense XML format (not pf syntax yet)")
    
    print("\n2️⃣  SAFETY BACKUP")
    print("   • Creates timestamped backup of /cf/conf/config.xml")
    print("   • Backup location: /cf/conf/config.xml.backup.{unix_timestamp}")
    print("   • Uses shutil.copy2() to preserve file metadata")
    
    print("\n3️⃣  CONFIGURATION MODIFICATION")
    print("   • Reads entire pfSense config file (typically 50-500KB)")
    print("   • Uses regex to replace ONLY the <filter>...</filter> section")
    print("   • Preserves all other settings (interfaces, NAT, DHCP, etc.)")
    print("   • Writes modified config back atomically")
    
    print("\n4️⃣  FIREWALL RELOAD ⭐ CRITICAL STEP")
    print("   • Executes: subprocess.run(['/etc/rc.filter_configure'])")
    print("   • This is pfSense's NATIVE rule reload mechanism")
    print("   • What /etc/rc.filter_configure does:")
    print("     a) Parses /cf/conf/config.xml")
    print("     b) Extracts <filter> section")
    print("     c) Converts XML rules to FreeBSD pf syntax")
    print("     d) Loads new rules into kernel via pfctl")
    print("     e) Activates rules immediately")
    
    print("\n5️⃣  VERIFICATION & ROLLBACK")
    print("   • Checks return code from /etc/rc.filter_configure")
    print("   • Return code 0 = Success, rules are now ACTIVE")
    print("   • Non-zero return code = Failure, triggers automatic rollback")
    print("   • Rollback restores backup and reports error")
    
    print("\n🔍 WHAT HAPPENS INSIDE /etc/rc.filter_configure:")
    print("-" * 40)
    print("This is a pfSense shell script that:")
    print("1. Sources pfSense PHP configuration libraries")
    print("2. Calls filter_configure() PHP function")
    print("3. Parses XML rules into internal data structures")
    print("4. Generates FreeBSD pf rules")
    print("5. Loads rules via: pfctl -f /tmp/rules.debug")
    print("6. Updates firewall state tables")
    print("7. Logs the reload event")
    
    print("\n📝 EXAMPLE RULE TRANSFORMATION:")
    print("-" * 40)
    
    print("XML INPUT (in config.xml):")
    xml_example = '''<rule>
    <type>block</type>
    <interface>wan</interface>
    <protocol>tcp</protocol>
    <source><any/></source>
    <destination>
        <network>wan</network>
        <port>22</port>
    </destination>
    <descr>Block SSH from WAN</descr>
</rule>'''
    print(xml_example)
    
    print("\nPF OUTPUT (loaded into kernel):")
    print("block in quick on em0 inet proto tcp from any to (em0) port 22")
    
    print("\n⚡ TIMING AND PERFORMANCE:")
    print("-" * 40)
    print("• Config file read/write: ~10-50ms")
    print("• Rule parsing and generation: ~100-500ms")
    print("• Kernel rule loading: ~50-200ms")
    print("• Total reload time: ~200ms-1s (depending on rule count)")
    print("• Brief traffic interruption during reload")
    print("• No reboot required - changes are immediate")
    
    print("\n🛡️  SAFETY MECHANISMS:")
    print("-" * 40)
    print("1. ATOMIC WRITES:")
    print("   • Config file written completely before reload")
    print("   • No partial updates that could corrupt firewall")
    
    print("\n2. AUTOMATIC ROLLBACK:")
    print("   • If reload fails, backup is immediately restored")
    print("   • System returns to last known good state")
    print("   • Error details captured and reported")
    
    print("\n3. VALIDATION:")
    print("   • pfSense validates XML syntax during reload")
    print("   • Invalid rules cause reload to fail safely")
    print("   • Rollback triggered on any validation error")
    
    print("\n4. LOGGING:")
    print("   • All reload attempts logged to system log")
    print("   • Success/failure status recorded")
    print("   • Backup file paths logged for recovery")
    
    print("\n🔧 FREEBSD PF INTEGRATION:")
    print("-" * 40)
    print("pfSense uses FreeBSD's Packet Filter (pf) as the underlying firewall:")
    print("• pf is a stateful firewall built into FreeBSD kernel")
    print("• Rules are loaded via pfctl command")
    print("• State tables track active connections")
    print("• Very high performance (millions of packets/second)")
    print("• Rules take effect immediately when loaded")
    
    print("\n📊 WHAT GETS RELOADED:")
    print("-" * 40)
    print("✅ Filter rules (block/pass)")
    print("✅ NAT rules (if modified)")
    print("✅ State table settings")
    print("✅ Interface assignments")
    print("✅ Traffic shaping (if configured)")
    print("❌ Interface IP addresses (separate process)")
    print("❌ Routing tables (separate process)")
    print("❌ System services (separate process)")
    
    print("\n🎯 WHY THIS APPROACH IS ROBUST:")
    print("-" * 40)
    print("1. NATIVE PFENSE METHOD:")
    print("   • Uses pfSense's own reload mechanism")
    print("   • Same process used by web GUI")
    print("   • Handles all edge cases and dependencies")
    
    print("\n2. BATTLE-TESTED:")
    print("   • Used by thousands of pfSense installations")
    print("   • Proven reliable over many years")
    print("   • Handles complex rule scenarios")
    
    print("\n3. COMPLETE INTEGRATION:")
    print("   • Updates all firewall components")
    print("   • Maintains state table consistency")
    print("   • Preserves active connections where possible")
    
    print("\n4. FAIL-SAFE:")
    print("   • Multiple layers of error detection")
    print("   • Automatic recovery on failure")
    print("   • No way to 'brick' the firewall")

def show_file_examples():
    """Show examples of the actual files involved"""
    
    print("\n📄 ACTUAL FILE EXAMPLES:")
    print("=" * 80)
    
    print("\nCONFIG.XML STRUCTURE (simplified):")
    config_example = '''<?xml version="1.0"?>
<pfsense>
    <version>2.7.0</version>
    <system>
        <hostname>firewall</hostname>
        <domain>local</domain>
    </system>
    <interfaces>
        <wan>
            <if>em0</if>
            <ipaddr>dhcp</ipaddr>
        </wan>
    </interfaces>
    <filter>                    ← THIS SECTION GETS REPLACED
        <rule>
            <type>pass</type>
            <interface>lan</interface>
            <source><network>lan</network></source>
            <destination><any/></destination>
        </rule>
    </filter>                   ← END REPLACEMENT
    <nat>...</nat>
    <dhcpd>...</dhcpd>
</pfsense>'''
    print(config_example)
    
    print("\nBACKUP FILE NAMING:")
    print("config.xml.backup.1728489123  ← Unix timestamp")
    print("config.xml.backup.1728489456  ← Multiple backups kept")
    print("config.xml.backup.1728489789")
    
    print("\nGENERATED PF RULES (/tmp/rules.debug):")
    pf_example = '''# pfSense rules generated from XML
set skip on lo0
scrub in all
block in quick on em0 inet proto tcp from any to (em0) port 22
pass in quick on em1 inet from 192.168.1.0/24 to any
pass out quick on em0 inet from (em0) to any'''
    print(pf_example)

if __name__ == "__main__":
    explain_pfsense_rule_loading()
    show_file_examples()
    
    print("\n🎉 SUMMARY:")
    print("=" * 80)
    print("The client loads new rules by modifying pfSense's config file")
    print("and using pfSense's native reload mechanism. This is:")
    print("✅ Safe (automatic backup/rollback)")
    print("✅ Fast (sub-second reload)")
    print("✅ Reliable (battle-tested)")
    print("✅ Complete (handles all rule types)")
    print("✅ Native (uses pfSense's own methods)")
    print("\nYour firewall rules will be applied immediately and safely! 🚀")

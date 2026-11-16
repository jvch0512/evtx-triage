module app;

import std.algorithm : canFind, endsWith, sort;
import std.array : appender, array;
import std.file : DirEntry, SpanMode, dirEntries, exists, getSize, isDir, isFile, isSymlink, read;
import std.path : baseName;
import std.stdio : stderr, stdout, write;
import std.string : leftJustify, toUpper;
import std.conv : to;
import core.stdc.stdlib : exit;

import evtx;

int usage()
{
    stderr.write("usage: evtx-triage PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n");
    return 2;
}

bool isLog(string p)
{
    return p.endsWith(".json") || p.endsWith(".jsonl") || p.endsWith(".ndjson");
}

string readText(string path)
{
    try
    {
        if (getSize(path) > 200_000_000) return "";
        return cast(string) read(path);
    }
    catch (Exception)
    {
        return "";
    }
}

int run(string[] args)
{
    string path;
    bool havePath, tsv;
    string failOn;
    for (size_t i = 1; i < args.length; i++)
    {
        auto a = args[i];
        if (a == "--tsv") tsv = true;
        else if (a == "--fail-on")
        {
            i++;
            if (i >= args.length || !["medium", "high", "critical"].canFind(args[i])) return usage();
            failOn = args[i];
        }
        else if (a.length > 1 && a[0] == '-') return usage();
        else if (havePath) return usage();
        else { path = a; havePath = true; }
    }
    if (!havePath) return usage();
    if (!exists(path))
    {
        stderr.write("error: no such file or directory: " ~ path ~ "\n");
        return 2;
    }
    while (path.length > 1 && path[$ - 1] == '/') path = path[0 .. $ - 1];

    string[][] files; // [relative, full]
    if (isDir(path))
    {
        foreach (DirEntry e; dirEntries(path, SpanMode.depth, false))
        {
            try
            {
                if (e.isSymlink || !e.isFile || !isLog(e.name)) continue;
                if (e.name.canFind("/.git/")) continue;
                files ~= [e.name.length > path.length + 1 ? e.name[path.length + 1 .. $] : e.name, e.name];
            }
            catch (Exception)
            {
            }
        }
        files.sort!((a, b) => a[0] < b[0]);
    }
    else
    {
        files ~= [baseName(path), path];
    }

    Finding[] all;
    foreach (f; files)
        all ~= audit(readText(f[1]), f[0]);
    auto fs = sortFindings(all);

    auto head = files.length.to!string ~ " files, " ~ fs.length.to!string ~ " findings";
    auto o = appender!string;
    o ~= (tsv ? "# " ~ head : head) ~ "\n";
    foreach (f; fs)
    {
        auto where = f.line > 0 ? f.file ~ ":" ~ f.line.to!string : f.file;
        if (tsv)
            o ~= f.sev ~ "\t" ~ f.rule ~ "\t" ~ where ~ "\t" ~ f.msg ~ "\n";
        else
        {
            o ~= leftJustify(toUpper(f.sev), 8) ~ " " ~ f.rule ~ " " ~ where ~ "\n";
            o ~= "         " ~ f.msg ~ "\n";
        }
    }
    stdout.write(o.data);
    stdout.flush();
    if (failOn.length)
        foreach (f; fs)
            if (rank(f.sev) <= rank(failOn)) return 1;
    return 0;
}

int main(string[] args)
{
    return run(args);
}

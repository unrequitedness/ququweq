using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using OfficeOpenXml;
using System.Data.SQLite;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<PersDb>(opts => opts.UseSqlite("Data Source=hhh.db"));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("suhenzmer1625347089suhenzmer1625347089"))
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddCors(opts => opts.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

var app = builder.Build();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "pmapi works. use /test to verify or /api/v1/ endpoints.");

app.MapPost("/api/v1/SignIn", async (HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<Usr>(ctx.Request.Body);
    if (body == null) return Results.BadRequest();

    var u = await db.Usrs.FirstOrDefaultAsync(x => x.Name == body.Name && x.Pwd == body.Pwd);
    if (u == null) return Results.Forbid();

    var h = new JwtSecurityTokenHandler();
    var k = Encoding.ASCII.GetBytes("suhenzmer1625347089suhenzmer1625347089");
    var t = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, u.Name) }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(k), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = h.CreateToken(t);
    return Results.Ok(new { Token = h.WriteToken(token) });
});

app.MapPost("/create-test-doc", async (PersDb db) =>
{
    var doc = new Doc 
    { 
        Title = "Test Document", 
        DateCrt = DateTime.UtcNow, 
        DateUpd = DateTime.UtcNow, 
        Cat = "Test", 
        HasCmt = false 
    };
    db.Docs.Add(doc);
    await db.SaveChangesAsync();
    return Results.Ok(new { doc.Id, doc.Title });
});

app.MapGet("/api/v1/Documents", async (PersDb db) =>
{
    var docs = await db.Docs.Select(d => new
    {
        d.Id,
        d.Title,
        d.DateCrt,
        d.DateUpd,
        d.Cat,
        d.HasCmt
    }).ToListAsync();
    return Results.Ok(docs);
}).RequireAuthorization();

app.MapPost("/api/v1/Document", async (HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<DocDto>(ctx.Request.Body);
    if (body == null || string.IsNullOrEmpty(body.Title) || string.IsNullOrEmpty(body.Category)) return Results.BadRequest("Invalid data");

    var doc = new Doc
    {
        Title = body.Title,
        DateCrt = DateTime.UtcNow,
        DateUpd = DateTime.UtcNow,
        Cat = body.Category,
        HasCmt = false
    };
    db.Docs.Add(doc);
    await db.SaveChangesAsync();
    return Results.Ok(new { Id = doc.Id });
}).RequireAuthorization();

app.MapGet("/api/v1/Document/{docId}/Comments", async (int docId, PersDb db) =>
{
    var cmts = await db.Cmts
        .Where(c => c.DocId == docId)
        .Select(c => new
        {
            c.Id,
            c.DocId,
            c.Text,
            c.DateCrt,
            c.DateUpd,
            Author = new { c.AuthName, c.AuthPos }
        }).ToListAsync();

    if (!cmts.Any())
        return Results.NotFound(new { ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), msg = "No comments", err = "2344" });

    return Results.Ok(cmts);
}).RequireAuthorization();

app.MapPost("/api/v1/Document/{docId}/Comment", async (int docId, HttpContext ctx, PersDb db) =>
{
    var c = await JsonSerializer.DeserializeAsync<CmtDto>(ctx.Request.Body);
    if (c == null || string.IsNullOrEmpty(c.Text) || string.IsNullOrEmpty(c.AuthName) || string.IsNullOrEmpty(c.AuthPos))
        return Results.BadRequest("Invalid data");

    var cmt = new Cmt
    {
        DocId = docId,
        Text = c.Text,
        DateCrt = DateTime.UtcNow,
        DateUpd = DateTime.UtcNow,
        AuthName = c.AuthName,
        AuthPos = c.AuthPos
    };
    db.Cmts.Add(cmt);
    await db.SaveChangesAsync();

    var doc = await db.Docs.FindAsync(docId);
    if (doc != null && !doc.HasCmt)
    {
        doc.HasCmt = true;
        await db.SaveChangesAsync();
    }

    return Results.Ok("Comment added");
}).RequireAuthorization();

app.MapGet("/api/v1/Departments", async (PersDb db) =>
{
    var depts = await db.Depts.Select(d => new
    {
        d.Id,
        d.Name,
        d.Desc,
        Manager = d.Mgr != null ? new { d.Mgr.Id, d.Mgr.Name, d.Mgr.Pos } : null,
        EmployeeCount = d.Emps.Count
    }).ToListAsync();
    return Results.Ok(depts);
}).RequireAuthorization();

app.MapGet("/api/v1/Department/{deptId}", async (int deptId, PersDb db) =>
{
    var dept = await db.Depts
        .Include(d => d.Mgr)
        .Include(d => d.Emps)
        .FirstOrDefaultAsync(d => d.Id == deptId);

    if (dept == null) return Results.NotFound();

    var result = new
    {
        dept.Id,
        dept.Name,
        dept.Desc,
        Manager = dept.Mgr != null ? new { dept.Mgr.Id, dept.Mgr.Name, dept.Mgr.Pos } : null,
        Employees = dept.Emps.Select(e => new
        {
            e.Id,
            e.Name,
            e.Pos,
            e.WorkPh,
            e.Mob,
            e.Email,
            e.Off
        })
    };
    return Results.Ok(result);
}).RequireAuthorization();

app.MapGet("/api/v1/Employees", async (PersDb db) =>
{
    var emps = await db.Emps.Select(e => new
    {
        e.Id,
        e.Name,
        Department = e.Dept.Name,
        e.Pos,
        e.WorkPh,
        e.Mob,
        e.Email,
        e.Off
    }).ToListAsync();
    return Results.Ok(emps);
}).RequireAuthorization();

app.MapGet("/api/v1/Employee/{empId}", async (int empId, PersDb db) =>
{
    var emp = await db.Emps
        .Include(e => e.Dept)
        .Include(e => e.Mgr)
        .Include(e => e.Asst)
        .FirstOrDefaultAsync(e => e.Id == empId);

    if (emp == null) return Results.NotFound();

    var trainings = await db.Trns.Where(t => t.Resp.Contains(emp.Name)).ToListAsync();
    var absences = await db.Abs.Where(a => a.EmpId == empId).ToListAsync();

    var result = new
    {
        emp.Id,
        emp.Name,
        emp.Mob,
        emp.Bday,
        Department = new { emp.Dept.Id, emp.Dept.Name },
        emp.Pos,
        Manager = emp.Mgr != null ? new { emp.Mgr.Id, emp.Mgr.Name } : null,
        Assistant = emp.Asst != null ? new { emp.Asst.Id, emp.Asst.Name } : null,
        emp.WorkPh,
        emp.Email,
        emp.Off,
        emp.Info,
        Trainings = trainings.Select(t => new { t.Id, t.Name, t.Date }),
        Absences = absences.Select(a => new { a.Id, a.Date, a.Type, Substitute = a.Sub != null ? a.Sub.Name : null }),
        Vacations = absences.Where(a => a.Type == "vacation").Select(a => new { a.Date })
    };
    return Results.Ok(result);
}).RequireAuthorization();

app.MapPut("/api/v1/Employee/{empId}", async (int empId, HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<EmpDto>(ctx.Request.Body);
    if (body == null) return Results.BadRequest();

    var emp = await db.Emps.FindAsync(empId);
    if (emp == null) return Results.NotFound();

    if (!string.IsNullOrEmpty(body.Mob) && body.Mob.Length > 20) return Results.BadRequest("Mobile too long");

    emp.Name = body.Name ?? emp.Name;
    emp.Mob = body.Mob ?? emp.Mob;
    emp.Bday = body.Bday ?? emp.Bday;
    emp.Pos = body.Pos ?? emp.Pos;
    emp.MgrId = body.MgrId ?? emp.MgrId;
    emp.AsstId = body.AsstId ?? emp.AsstId;
    emp.WorkPh = body.WorkPh ?? emp.WorkPh;
    emp.Email = body.Email ?? emp.Email;
    emp.Off = body.Off ?? emp.Off;
    emp.Info = body.Info ?? emp.Info;

    await db.SaveChangesAsync();
    return Results.Ok();
}).RequireAuthorization();

app.MapPut("/api/v1/MyProfile", async (HttpContext ctx, PersDb db) =>
{
    var userName = ctx.User.Identity?.Name;
    if (string.IsNullOrEmpty(userName)) return Results.Unauthorized();

    var body = await JsonSerializer.DeserializeAsync<SelfEditDto>(ctx.Request.Body);
    if (body == null) return Results.BadRequest();

    var emp = await db.Emps.FirstOrDefaultAsync(e => e.Name == userName);
    if (emp == null) return Results.NotFound();

    emp.Mob = body.Mob ?? emp.Mob;
    emp.Bday = body.Bday ?? emp.Bday;

    await db.SaveChangesAsync();
    return Results.Ok();
}).RequireAuthorization();

app.MapGet("/api/v1/Trainings", async (PersDb db) =>
{
    var trns = await db.Trns.Select(t => new
    {
        t.Id,
        t.Name,
        t.Type,
        t.Stat,
        t.Date,
        t.Resp,
        t.Desc,
        MaterialsCount = t.Mats.Count
    }).ToListAsync();
    return Results.Ok(trns);
}).RequireAuthorization();

app.MapGet("/api/v1/Training/{trnId}", async (int trnId, PersDb db) =>
{
    var trn = await db.Trns
        .Include(t => t.Mats)
        .FirstOrDefaultAsync(t => t.Id == trnId);

    if (trn == null) return Results.NotFound();

    var result = new
    {
        trn.Id,
        trn.Name,
        trn.Type,
        trn.Stat,
        trn.Date,
        trn.Resp,
        trn.Desc,
        Materials = trn.Mats.Select(m => new
        {
            m.Id,
            m.Name,
            m.ApprDate,
            m.UpdDate,
            m.Stat,
            m.Type,
            m.Area,
            m.Auth
        })
    };
    return Results.Ok(result);
}).RequireAuthorization();

app.MapPost("/api/v1/Training", async (HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<TrnDto>(ctx.Request.Body);
    if (body == null || string.IsNullOrEmpty(body.Name) || string.IsNullOrEmpty(body.Type)) return Results.BadRequest();

    var trn = new Trn
    {
        Name = body.Name,
        Type = body.Type,
        Stat = body.Stat ?? "Planned",
        Date = body.Date,
        Resp = body.Resp,
        Desc = body.Desc
    };
    db.Trns.Add(trn);
    await db.SaveChangesAsync();
    return Results.Ok(new { Id = trn.Id });
}).RequireAuthorization();

app.MapGet("/api/v1/Materials", async (PersDb db) =>
{
    var mats = await db.Mats.Select(m => new
    {
        m.Id,
        m.Name,
        m.ApprDate,
        m.UpdDate,
        m.Stat,
        m.Type,
        m.Area,
        m.Auth,
        TrainingId = m.TrnId
    }).ToListAsync();
    return Results.Ok(mats);
}).RequireAuthorization();

app.MapPost("/api/v1/Material", async (HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<MatDto>(ctx.Request.Body);
    if (body == null || string.IsNullOrEmpty(body.Name)) return Results.BadRequest();

    var mat = new Mat
    {
        Name = body.Name,
        ApprDate = body.ApprDate,
        UpdDate = body.UpdDate ?? DateTime.UtcNow,
        Stat = body.Stat ?? "Draft",
        Type = body.Type,
        Area = body.Area,
        Auth = body.Auth,
        TrnId = body.TrnId ?? 0
    };
    db.Mats.Add(mat);
    await db.SaveChangesAsync();
    return Results.Ok(new { Id = mat.Id });
}).RequireAuthorization();

app.MapPut("/api/v1/Material/{matId}", async (int matId, HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<MatDto>(ctx.Request.Body);
    if (body == null) return Results.BadRequest();

    var mat = await db.Mats.FindAsync(matId);
    if (mat == null) return Results.NotFound();

    mat.Name = body.Name ?? mat.Name;
    mat.ApprDate = body.ApprDate != default ? body.ApprDate : mat.ApprDate;
    mat.UpdDate = DateTime.UtcNow;
    mat.Stat = body.Stat ?? mat.Stat;
    mat.Type = body.Type ?? mat.Type;
    mat.Area = body.Area ?? mat.Area;
    mat.Auth = body.Auth ?? mat.Auth;
    mat.TrnId = body.TrnId ?? mat.TrnId;

    await db.SaveChangesAsync();
    return Results.Ok();
}).RequireAuthorization();

app.MapGet("/api/v1/Absences", async (PersDb db) =>
{
    var abs = await db.Abs
        .Include(a => a.Emp)
        .Include(a => a.Sub)
        .Select(a => new
        {
            a.Id,
            Employee = new { a.Emp.Id, a.Emp.Name },
            a.Date,
            a.Type,
            Substitute = a.Sub != null ? new { a.Sub.Id, a.Sub.Name } : null
        }).ToListAsync();
    return Results.Ok(abs);
}).RequireAuthorization();

app.MapPost("/api/v1/Absence", async (HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<AbsDto>(ctx.Request.Body);
    if (body == null || body.EmpId == 0 || string.IsNullOrEmpty(body.Type)) return Results.BadRequest();

    var abs = new Abs
    {
        EmpId = body.EmpId,
        Date = body.Date,
        Type = body.Type,
        SubId = body.SubId
    };
    db.Abs.Add(abs);
    await db.SaveChangesAsync();
    return Results.Ok(new { Id = abs.Id });
}).RequireAuthorization();

app.MapGet("/api/v1/Resumes", async (PersDb db) =>
{
    var res = await db.Ress.Select(r => new
    {
        r.Id,
        r.CandName,
        r.Dir,
        r.SubDate,
        r.Dets
    }).ToListAsync();
    return Results.Ok(res);
}).RequireAuthorization();

app.MapGet("/api/v1/Resume/{resId}", async (int resId, PersDb db) =>
{
    var res = await db.Ress.FindAsync(resId);
    if (res == null) return Results.NotFound();
    return Results.Ok(res);
}).RequireAuthorization();

app.MapPost("/api/v1/Resume", async (HttpContext ctx, PersDb db) =>
{
    var body = await JsonSerializer.DeserializeAsync<ResDto>(ctx.Request.Body);
    if (body == null || string.IsNullOrEmpty(body.CandName)) return Results.BadRequest();

    var res = new Res
    {
        CandName = body.CandName,
        Dir = body.Dir,
        SubDate = body.SubDate,
        Dets = body.Dets
    };
    db.Ress.Add(res);
    await db.SaveChangesAsync();
    return Results.Ok(new { Id = res.Id });
}).RequireAuthorization();

app.MapPost("/initdb", (PersDb db) =>
{
    db.Database.EnsureCreated();
    return Results.Ok();
});

app.MapPost("/create-test-user", async (PersDb db) =>
{
    var testUser = new Usr { Name = "test", Pwd = "123" };
    db.Usrs.Add(testUser);
    await db.SaveChangesAsync();
    return Results.Ok("Test user created");
});

app.MapPost("/imporg", async (HttpContext ctx) =>
{
    var xlsx = ctx.Request.Form.Files[0];
    if (xlsx == null) return Results.BadRequest();

    ExcelPackage.LicenseContext = LicenseContext.NonCommercial;

    using var stream = xlsx.OpenReadStream();
    using var pkg = new ExcelPackage(stream);
    var ws = pkg.Workbook.Worksheets[0];
    using var db = ctx.RequestServices.GetRequiredService<PersDb>();

    for (int r = 2; r <= ws.Dimension.Rows; r++)
    {
        var deptName = ws.Cells[r, 1].Text;
        var deptDesc = ws.Cells[r, 2].Text;

        var existingDept = await db.Depts.FirstOrDefaultAsync(d => d.Name == deptName);
        Dept d;
        if (existingDept == null)
        {
            d = new Dept
            {
                Name = deptName,
                Desc = deptDesc,
            };
            db.Depts.Add(d);
            await db.SaveChangesAsync();
        }
        else
        {
            d = existingDept;
        }

        var e = new Emp
        {
            Name = ws.Cells[r, 3].Text,
            DeptId = d.Id,
            Pos = ws.Cells[r, 4].Text,
            WorkPh = ws.Cells[r, 5].Text,
            Mob = ws.Cells[r, 6].Text,
            Email = ws.Cells[r, 7].Text,
            Off = ws.Cells[r, 8].Text,
        };
        db.Emps.Add(e);
    }
    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPost("/impcal", async (HttpContext ctx) =>
{
    var sqlFile = ctx.Request.Form.Files[0];
    if (sqlFile == null) return Results.BadRequest();

    using var stream = sqlFile.OpenReadStream();
    using var reader = new StreamReader(stream);
    var s = await reader.ReadToEndAsync();
    using var conn = new SQLiteConnection("Data Source=hhh.db");
    await conn.OpenAsync();
    using var cmd = new SQLiteCommand(s, conn);
    await cmd.ExecuteNonQueryAsync();
    return Results.Ok();
});

app.MapGet("/test", () => "API is running!");

app.Run();

public class Emp
{
    public int Id { get; set; }
    [Required]
    public string Name { get; set; } = string.Empty;
    [MaxLength(20)]
    public string Mob { get; set; } = string.Empty;
    public DateTime? Bday { get; set; }
    public int DeptId { get; set; }
    [Required]
    public string Pos { get; set; } = string.Empty;
    public int? MgrId { get; set; }
    public int? AsstId { get; set; }
    [Required, MaxLength(20)]
    public string WorkPh { get; set; } = string.Empty;
    [Required, MaxLength(255), EmailAddress]
    public string Email { get; set; } = string.Empty;
    [Required, MaxLength(10)]
    public string Off { get; set; } = string.Empty;
    public string Info { get; set; } = string.Empty;
    public Dept Dept { get; set; } = null!;
    public Emp? Mgr { get; set; }
    public Emp? Asst { get; set; }
}

public class Dept
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Desc { get; set; } = string.Empty;
    public int? MgrId { get; set; }
    public Emp? Mgr { get; set; }
    public List<Emp> Emps { get; set; } = new();
}

public class Trn
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Stat { get; set; } = string.Empty;
    public DateTime Date { get; set; }
    public string Resp { get; set; } = string.Empty;
    public string Desc { get; set; } = string.Empty;
    public List<Mat> Mats { get; set; } = new();
}

public class Mat
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTime ApprDate { get; set; }
    public DateTime UpdDate { get; set; }
    public string Stat { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Area { get; set; } = string.Empty;
    public string Auth { get; set; } = string.Empty;
    public int TrnId { get; set; }
    public Trn Trn { get; set; } = null!;
}

public class Abs
{
    public int Id { get; set; }
    public int EmpId { get; set; }
    public DateTime Date { get; set; }
    public string Type { get; set; } = string.Empty;
    public int? SubId { get; set; }
    public Emp Emp { get; set; } = null!;
    public Emp? Sub { get; set; }
}

public class Res
{
    public int Id { get; set; }
    public string CandName { get; set; } = string.Empty;
    public string Dir { get; set; } = string.Empty;
    public DateTime SubDate { get; set; }
    public string Dets { get; set; } = string.Empty;
}

public class Doc
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public DateTime DateCrt { get; set; }
    public DateTime DateUpd { get; set; }
    public string Cat { get; set; } = string.Empty;
    public bool HasCmt { get; set; }
}

public class Cmt
{
    public int Id { get; set; }
    public int DocId { get; set; }
    public string Text { get; set; } = string.Empty;
    public DateTime DateCrt { get; set; }
    public DateTime DateUpd { get; set; }
    public string AuthName { get; set; } = string.Empty;
    public string AuthPos { get; set; } = string.Empty;
}

public class Usr
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Pwd { get; set; } = string.Empty;
}

public class PersDb : DbContext
{
    public DbSet<Emp> Emps { get; set; } = null!;
    public DbSet<Dept> Depts { get; set; } = null!;
    public DbSet<Trn> Trns { get; set; } = null!;
    public DbSet<Mat> Mats { get; set; } = null!;
    public DbSet<Abs> Abs { get; set; } = null!;
    public DbSet<Res> Ress { get; set; } = null!;
    public DbSet<Doc> Docs { get; set; } = null!;
    public DbSet<Cmt> Cmts { get; set; } = null!;
    public DbSet<Usr> Usrs { get; set; } = null!;

    public PersDb(DbContextOptions<PersDb> opts) : base(opts) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Emp>().Property(e => e.Name).IsUnicode(true);
        modelBuilder.Entity<Emp>().Property(e => e.Mob).HasMaxLength(20);
        modelBuilder.Entity<Emp>().Property(e => e.WorkPh).HasMaxLength(20);
        modelBuilder.Entity<Emp>().Property(e => e.Email).HasMaxLength(255);
        modelBuilder.Entity<Emp>().Property(e => e.Off).HasMaxLength(10);
        modelBuilder.Entity<Emp>().Property(e => e.Pos).IsUnicode(true);
        modelBuilder.Entity<Emp>().Property(e => e.Info).IsUnicode(true);

        modelBuilder.Entity<Emp>().HasOne(e => e.Mgr).WithMany().HasForeignKey(e => e.MgrId).OnDelete(DeleteBehavior.NoAction);
        modelBuilder.Entity<Emp>().HasOne(e => e.Asst).WithMany().HasForeignKey(e => e.AsstId).OnDelete(DeleteBehavior.NoAction);
        modelBuilder.Entity<Emp>().HasOne(e => e.Dept).WithMany(d => d.Emps).HasForeignKey(e => e.DeptId);

        modelBuilder.Entity<Dept>().Property(d => d.Name).IsUnicode(true);
        modelBuilder.Entity<Dept>().Property(d => d.Desc).IsUnicode(true);
        modelBuilder.Entity<Dept>().HasOne(d => d.Mgr).WithMany().HasForeignKey(d => d.MgrId);

        modelBuilder.Entity<Trn>().Property(t => t.Name).IsUnicode(true);
        modelBuilder.Entity<Trn>().Property(t => t.Type).IsUnicode(true);
        modelBuilder.Entity<Trn>().Property(t => t.Stat).IsUnicode(true);
        modelBuilder.Entity<Trn>().Property(t => t.Resp).IsUnicode(true);
        modelBuilder.Entity<Trn>().Property(t => t.Desc).IsUnicode(true);

        modelBuilder.Entity<Mat>().Property(m => m.Name).IsUnicode(true);
        modelBuilder.Entity<Mat>().Property(m => m.Stat).IsUnicode(true);
        modelBuilder.Entity<Mat>().Property(m => m.Type).IsUnicode(true);
        modelBuilder.Entity<Mat>().Property(m => m.Area).IsUnicode(true);
        modelBuilder.Entity<Mat>().Property(m => m.Auth).IsUnicode(true);
        modelBuilder.Entity<Mat>().HasOne(m => m.Trn).WithMany(t => t.Mats).HasForeignKey(m => m.TrnId);

        modelBuilder.Entity<Abs>().Property(a => a.Type).IsUnicode(true);
        modelBuilder.Entity<Abs>().HasOne(a => a.Emp).WithMany().HasForeignKey(a => a.EmpId);
        modelBuilder.Entity<Abs>().HasOne(a => a.Sub).WithMany().HasForeignKey(a => a.SubId).OnDelete(DeleteBehavior.NoAction);

        modelBuilder.Entity<Res>().Property(r => r.CandName).IsUnicode(true);
        modelBuilder.Entity<Res>().Property(r => r.Dir).IsUnicode(true);
        modelBuilder.Entity<Res>().Property(r => r.Dets).IsUnicode(true);

        modelBuilder.Entity<Doc>().Property(d => d.Title).IsUnicode(true);
        modelBuilder.Entity<Doc>().Property(d => d.Cat).IsUnicode(true);

        modelBuilder.Entity<Cmt>().Property(c => c.Text).IsUnicode(true);
        modelBuilder.Entity<Cmt>().Property(c => c.AuthName).IsUnicode(true);
        modelBuilder.Entity<Cmt>().Property(c => c.AuthPos).IsUnicode(true);

        modelBuilder.Entity<Usr>().Property(u => u.Name).IsUnicode(true);
        modelBuilder.Entity<Usr>().Property(u => u.Pwd).IsUnicode(true);
    }
}

public class DocDto
{
    public string? Title { get; set; }
    public string? Category { get; set; }
}

public class CmtDto
{
    public string? Text { get; set; }
    public string? AuthName { get; set; }
    public string? AuthPos { get; set; }
}

public class EmpDto
{
    public string? Name { get; set; }
    public string? Mob { get; set; }
    public DateTime? Bday { get; set; }
    public string? Pos { get; set; }
    public int? MgrId { get; set; }
    public int? AsstId { get; set; }
    public string? WorkPh { get; set; }
    public string? Email { get; set; }
    public string? Off { get; set; }
    public string? Info { get; set; }
}

public class SelfEditDto
{
    public string? Mob { get; set; }
    public DateTime? Bday { get; set; }
}

public class TrnDto
{
    public string? Name { get; set; }
    public string? Type { get; set; }
    public string? Stat { get; set; }
    public DateTime Date { get; set; }
    public string? Resp { get; set; }
    public string? Desc { get; set; }
}

public class MatDto
{
    public string? Name { get; set; }
    public DateTime ApprDate { get; set; }
    public DateTime? UpdDate { get; set; }
    public string? Stat { get; set; }
    public string? Type { get; set; }
    public string? Area { get; set; }
    public string? Auth { get; set; }
    public int? TrnId { get; set; }
}

public class AbsDto
{
    public int EmpId { get; set; }
    public DateTime Date { get; set; }
    public string? Type { get; set; }
    public int? SubId { get; set; }
}

public class ResDto
{
    public string? CandName { get; set; }
    public string? Dir { get; set; }
    public DateTime SubDate { get; set; }
    public string? Dets { get; set; }
}
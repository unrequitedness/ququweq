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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("suhenzmer1625347089"))
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddCors();

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
    var k = Encoding.ASCII.GetBytes("suhenzmer1625347089");
    var t = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, u.Name) }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(k), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = h.CreateToken(t);
    return Results.Ok(new { Token = h.WriteToken(token) });
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
    var c = await JsonSerializer.DeserializeAsync<Cmt>(ctx.Request.Body);
    if (c == null || string.IsNullOrEmpty(c.Text)) return Results.BadRequest("Invalid data");

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

    return Results.Ok("Comment added");
}).RequireAuthorization();

app.MapPost("/initdb", (PersDb db) =>
{
    db.Database.EnsureCreated();
    return Results.Ok();
});

app.MapPost("/imporg", async (HttpContext ctx) =>
{
    var xlsx = ctx.Request.Form.Files[0];
    if (xlsx == null) return Results.BadRequest();

    ExcelPackage.License.SetNonCommercialPersonal("Determinacy");

    using var stream = xlsx.OpenReadStream();
    using var pkg = new ExcelPackage(stream);
    var ws = pkg.Workbook.Worksheets[0];
    using var db = ctx.RequestServices.GetRequiredService<PersDb>();

    for (int r = 2; r <= ws.Dimension.Rows; r++)
    {
        var d = new Dept
        {
            Name = ws.Cells[r, 1].Text,
            Desc = ws.Cells[r, 2].Text,
        };
        db.Depts.Add(d);
        await db.SaveChangesAsync();

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
    public string Name { get; set; } = string.Empty;
    public string Mob { get; set; } = string.Empty;
    public DateTime? Bday { get; set; }
    public int DeptId { get; set; }
    public string Pos { get; set; } = string.Empty;
    public int? MgrId { get; set; }
    public int? AsstId { get; set; }
    public string WorkPh { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Off { get; set; } = string.Empty;
    public string Info { get; set; } = string.Empty;
    public Dept Dept { get; set; } = null!;
}

public class Dept
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Desc { get; set; } = string.Empty;
    public int? MgrId { get; set; }
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
}

public class Abs
{
    public int Id { get; set; }
    public int EmpId { get; set; }
    public DateTime Date { get; set; }
    public string Type { get; set; } = string.Empty;
    public int? SubId { get; set; }
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
    }
}

public class Usr
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Pwd { get; set; } = string.Empty;
}
using Microsoft.AspNetCore.Identity;

namespace CistaNAS.Web.Identity;

public sealed class ApplicationRole : IdentityRole<string>
{
    public ApplicationRole() { Id = Guid.NewGuid().ToString(); }
    public ApplicationRole(string roleName) : base(roleName) { Id = Guid.NewGuid().ToString(); }
}

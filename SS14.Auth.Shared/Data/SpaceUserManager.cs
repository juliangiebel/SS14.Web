using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SS14.Auth.Shared.Data;

[UsedImplicitly]
public sealed class SpaceUserManager(
    ApplicationDbContext dbContext,
    ISystemClock systemClock,
    IUserStore<SpaceUser> store,
    IOptions<IdentityOptions> optionsAccessor,
    IPasswordHasher<SpaceUser> passwordHasher,
    IEnumerable<IUserValidator<SpaceUser>> userValidators,
    IEnumerable<IPasswordValidator<SpaceUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<SpaceUser>> logger)
    : UserManager<SpaceUser>(
        store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer,
        errors, services, logger)
{
    private readonly IServiceProvider _services = services;

    public override async Task<IdentityResult> CreateAsync(SpaceUser user)
    {
        var result = await base.CreateAsync(user);
        if (!result.Succeeded)
            return result;

        // We can't directly depend on AccountLogManager due to a circular dependency.
        // Whoopsie.
        var accountLogManager = _services.GetRequiredService<AccountLogManager>();
        await accountLogManager.LogAndSave(user, new AccountLogCreated(), accountLogManager.NoActor());
        return result;
    }

    public async Task<SpaceUser> FindByNameOrEmailAsync(string nameOrEmail)
    {
        var user = await FindByNameAsync(nameOrEmail);
        if (user != null)
        {
            return user;
        }

        return await FindByEmailAsync(nameOrEmail);
    }

    public void QueueDeletion(SpaceUser user)
    {
        dbContext.UserDeletionQueue.Add(new UserDeletionQueueEntry {SpaceUserId = user.Id, QueuedOn = DateTime.UtcNow });
        dbContext.SaveChanges();
    }

    ///<inheritdoc />
    /// <remarks>
    /// Stores the deleted user in the DeletedUserIds table.
    /// </remarks>
    public override async  Task<IdentityResult> DeleteAsync(SpaceUser user)
    {
        dbContext.DeletedUserIds.Add(new DeletedUser { SpaceUserId = user.Id, DeletedOn = DateTime.UtcNow });
        return await base.DeleteAsync(user);
    }
}

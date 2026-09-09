using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>Mobile.Core の共有 v2 セッション状態 (E2eeSession / E2eeV2VolumeState) のテスト。</summary>
public class MobileV2StateTests
{
    [Fact]
    public void E2eeV2VolumeState_ManagesEpochsAndVolumeId()
    {
        var keys = new Dictionary<int, byte[]>
        {
            [1] = E2eeV2.GenerateGroupKey(),
            [2] = E2eeV2.GenerateGroupKey(),
        };
        using var state = new E2eeV2VolumeState("vol-abc", keys);

        Assert.Equal("vol-abc", state.VolumeIdString);
        Assert.Equal(2, state.CurrentEpoch); // 新規書き込みに使うのは最新 epoch
        Assert.True(state.HasEpoch(1));
        Assert.False(state.HasEpoch(3));
        Assert.Equal(keys[1], state.GetGroupKey(1));
        // 権限のない（wrap を持たない）epoch の取得は例外
        Assert.Throws<InvalidOperationException>(() => state.GetGroupKey(3));
    }

    [Fact]
    public void E2eeV2VolumeState_RejectsWrongKeySize()
    {
        var keys = new Dictionary<int, byte[]> { [1] = new byte[16] };
        Assert.Throws<ArgumentException>(() => new E2eeV2VolumeState("vol", keys));
    }

    [Fact]
    public void E2eeSession_StoresAndRemovesV2State()
    {
        using var session = new E2eeSession();
        var keys = new Dictionary<int, byte[]> { [1] = E2eeV2.GenerateGroupKey() };

        Assert.False(session.HasV2State("vol"));
        Assert.False(session.TryGetV2State("vol", out _));
        Assert.Throws<InvalidOperationException>(() => session.GetV2State("vol"));

        session.StoreV2State("vol", "vol-abc", keys);
        Assert.True(session.HasV2State("vol"));
        Assert.True(session.TryGetV2State("vol", out var s));
        Assert.Equal("vol-abc", s!.VolumeIdString);
        Assert.Equal(1, s!.CurrentEpoch);

        // ロック (RemoveKey) で v2 状態も破棄される
        Assert.True(session.RemoveKey("vol"));
        Assert.False(session.HasV2State("vol"));
    }
}

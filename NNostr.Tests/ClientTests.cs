using System;
using NBitcoin.Secp256k1;
using NNostr.Client;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Xunit;

namespace NNostr.Tests;

public class ClientTests
{
    private (ECPrivKey PrivateKey, string PrivateKeyHex, ECXOnlyPubKey PublicKey, string PublicKeyHex) CreateUser(
        string privKeyHex)
    {
        Assert.True(Context.Instance.TryCreateECPrivKey(Convert.FromHexString(privKeyHex), out var privKey));
        Debug.Assert(privKey != null, nameof(privKey) + " != null");
        return (privKey, privKeyHex,
            privKey.CreateXOnlyPubKey(), privKey.CreateXOnlyPubKey().ToBytes().AsSpan().ToHex());
    }

    [Fact]
    public async Task CanHandleNIP04()
    {
        var user1 = CreateUser("7f4c11a9742721d66e40e321ca50b682c27f7422190c14a187525e69e604836a");
        var user2 = CreateUser("203b892f1d671fec43a04b36c452de631c9cf55b7a93b75d97ff1e41d217f038");
        var evtFromUser1ToUser2 = new NostrEvent()
        {
            Content = "test",
            Kind = 4,
            Tags = new List<NostrEventTag>()
            {
                new()
                {
                    TagIdentifier = "p",
                    Data = new List<string>()
                    {
                        user2.PublicKeyHex
                    }
                }
            }
        };

        await evtFromUser1ToUser2.EncryptNip04EventAsync(user1.PrivateKey);
        Assert.Equal("test", await evtFromUser1ToUser2.DecryptNip04EventAsync(user2.PrivateKey));
        Assert.Equal("test", await evtFromUser1ToUser2.DecryptNip04EventAsync(user1.PrivateKey));
    }

    [Fact]
    public void CanHandlePrivatePublicKeyFormats()
    {
        var privKeyHex = "7f4c11a9742721d66e40e321ca50b682c27f7422190c14a187525e69e604836a";
        Assert.True(Context.Instance.TryCreateECPrivKey(Convert.FromHexString(privKeyHex), out var privKey));
        Debug.Assert(privKey != null, nameof(privKey) + " != null");
        var pubKey = privKey.CreateXOnlyPubKey();
        Assert.Equal("7cef86754ddf07395c289c30fe31219de938c6d707d6b478a8682fc75795e8b9",
            pubKey.ToBytes().AsSpan().ToHex());
    }
}
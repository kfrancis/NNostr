using Microsoft.VisualStudio.TestPlatform.Utilities;
using NBitcoin.Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit.Abstractions;
using Xunit;
using NNostr.Client;
using Xunit.Sdk;
using Shouldly;
using Bogus;

namespace NNostr.Tests
{
    public class Nip4Tests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public Nip4Tests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public static bool IsBase64String(string base64)
        {
            var buffer = new Span<byte>(new byte[base64.Length]);
            return Convert.TryFromBase64String(base64, buffer, out var _);
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        [Fact]
        public void Generate1000()
        {
            try
            {
                for (var i = 0; i < 1000; i++)
                {
                    _ = NostrClient.GenerateKey();
                }
            }
            catch
            {
                Assert.Fail("Could not complete without error");
            }
        }

        [Fact]
        public void CanGenerateEncryptableEvent()
        {
            var randomSender = NostrClient.GenerateKey();

            randomSender.ShouldSatisfyAllConditions(
                x => x.PrivateKey.ShouldNotBeNullOrEmpty(),
                x => x.PrivateKey.Length.ShouldBe(64),
                x => x.PublicKey.ShouldNotBeNullOrEmpty(),
                x => x.PublicKey.Length.ShouldBe(64)
            );

            var (ev, receiverKp) = GivenSampleEvent(randomSender.PublicKey);

            receiverKp.ShouldSatisfyAllConditions(
                kp => kp.PrivateKey.ShouldNotBeNullOrEmpty(),
                kp => kp.PrivateKey.Length.ShouldBe(64),
                kp => kp.PublicKey.ShouldNotBeNullOrEmpty(),
                kp => kp.PublicKey.Length.ShouldBe(64),
                kp => kp.PublicKey.ShouldNotBe(randomSender.PublicKey),
                kp => kp.PublicKey.ShouldNotBe(randomSender.PrivateKey),
                kp => kp.PrivateKey.ShouldNotBe(randomSender.PublicKey),
                kp => kp.PrivateKey.ShouldNotBe(randomSender.PrivateKey)
            );

            ev.ShouldSatisfyAllConditions(
                x => x.ShouldNotBeNull(),
                x => x.Tags.ShouldNotBeNull(),
                x => x.Tags.Count.ShouldBe(1),
                x => x.Tags.Any(t => t.Data.Contains(receiverKp.PublicKey)).ShouldBeTrue(),
                x => x.PublicKey.ShouldNotBeNullOrEmpty(),
                x => x.Content.ShouldNotBeNullOrEmpty(),
                x => x.Kind.ShouldBe((int)NostrKind.EncryptedDM),
                x => x.PublicKey.ShouldBe(randomSender.PublicKey),
                x => x.PublicKey.ShouldNotBe(randomSender.PrivateKey)
            );
        }

        [Theory]
        [InlineData("River", "4bf4bd8479c9d7253ed2e7a5716ac5d0c601aa10d9882a41b48655df960eb5ce", "9b05b0b7720cf589d7f7225a183b480ab455d84eacf4e49b231c5feebde631f9", "5535554debf50f8ca351b6abdfd67d154ab753a2d9f4bfed52be8e14316f6745", "RwegVk64f54UN1G2Ee/rAg==?iv=CUMTDSvq90nxu+UaNybIgg==")]
        [InlineData("Brand California Intelligent Cotton Mouse", "bffdfa000ae5619d9de900bd11a3db98aee2d71d4d69f9735fc7a7fec4f00d80", "9c5380be4c1c1322024189946cb7cc4f9c33b4ba19b3db43b3206a7b0a2ff90d", "42d54c5e99acc40c09180fb2bf9c3f392bbcf30ac5f1e25f90d771c442f08757", "OtENCdrbn1Vl/Jgw4x9/clENaPbB/vUmcz9FKgHkQNxG1t+06wJzRhrzXPOIxsZI?iv=NeGJW5ju87aqKncs7qikQQ==")]
        [InlineData("Operations hack", "7428e5b7df3ee9305942aa133619f32db28c6fc1d08067c2e45ebac0732cd559", "ec657f696d8abefdddf78c9df3d809546617bf4a55a462ed8bfea4f1f7ca0579", "df59dac9033f14084b87e9ffba1ec690f859033c9410812745ad95f3b1bee19d", "48hVZkj/XC2xKDgioN2ghw==?iv=ODh6srH5WsmrP9T0CrPUjQ==")]
        public async Task Nip04_CanDecrypt(string content, string senderPub, string receiverPub, string receiverPriv, string encContent)
        {
            // Arrange
            var (ev, receiverKp) = GivenSampleEvent(senderPub, encContent);
            ev.Tags.Clear();
            ev.Tags.Add(new NostrEventTag() { TagIdentifier = "p", Data = new List<string>() { receiverPub } });

            // Act
            await ev.DecryptNip04EventAsync(WithKey(receiverPriv));

            // Assert
            ev.Content.ShouldSatisfyAllConditions(
                x => x.ShouldNotBeNullOrEmpty(),
                x => x.ShouldBe(content)
            );
        }

        [Fact]
        public async Task Nip04_CanEncrypt()
        {
            // Arrange
            var randomSender = NostrClient.GenerateKey();
            var (ev, receiverKp) = GivenSampleEvent(randomSender.PublicKey);
            var origialContent = ev.Content;

            // Act
            await ev.EncryptNip04EventAsync(WithKey(randomSender.PrivateKey));

            // Assert
            ev.ShouldSatisfyAllConditions(
                e => e.Tags.Any(t => t.Data.Contains(receiverKp.PublicKey)).ShouldBeTrue(),
                e => e.PublicKey.ShouldBe(randomSender.PublicKey)
            );

            ev.Content.ShouldSatisfyAllConditions(
                x => x.ShouldNotBeNullOrEmpty(),
                x => x?.ShouldContain("?iv"),
                x => x?.ShouldNotContain(origialContent!),
                x => IsBase64String(x?.Split("?iv=")[0] ?? string.Empty).ShouldBeTrue(),    // encrypted content should be base64
                x => IsBase64String(x?.Split("?iv=")[1] ?? string.Empty).ShouldBeTrue()     // iv should be base64
            );

            _testOutputHelper.WriteLine("Content: " + origialContent);
            _testOutputHelper.WriteLine("SenderPub: " + randomSender.PublicKey);
            _testOutputHelper.WriteLine("ReceiverPub: " + receiverKp.PublicKey);
            _testOutputHelper.WriteLine("ReceiverPriv: " + receiverKp.PrivateKey);
            _testOutputHelper.WriteLine("EncContent: " + ev.Content);
            _testOutputHelper.WriteLine($"\n[InlineData(\"{origialContent}\",\"{randomSender.PublicKey}\",\"{receiverKp.PublicKey}\",\"{receiverKp.PrivateKey}\",\"{ev.Content}\")]");
        }

        private static (NostrEvent ev, (string PublicKey, string PrivateKey) receiverKp) GivenSampleEvent(string senderPubKey, string? content = null)
        {
            var randomReceiver = NostrClient.GenerateKey();
            var faker = new Faker<NostrEvent>()
                .RuleFor(e => e.Content, f => f.Random.Words(f.Random.Int(1, 3)));

            var e = faker.Generate(1)[0];
            e.Kind = (int)NostrKind.EncryptedDM;
            if (!string.IsNullOrEmpty(content))
            {
                e.Content = content; // overwrite if there's content passed in
            }
            e.PublicKey = senderPubKey;
            e.Tags ??= new();
            e.Tags.Add(new NostrEventTag() { TagIdentifier = "p", Data = new List<string>() { randomReceiver.PublicKey } });
            return (e, randomReceiver);
        }

        /// <summary>
        /// Provide a random private key or a formatted private key from string param
        /// </summary>
        /// <param name="privateKey">The hex private key</param>
        /// <returns>The ECPrivKey</returns>
        private static ECPrivKey WithKey(string? privateKey = null)
        {
            if (!string.IsNullOrEmpty(privateKey))
            {
                return Context.Instance.CreateECPrivKey(StringToByteArray(privateKey));
            }
            else
            {
                var keys = NostrClient.GenerateKey();
                return Context.Instance.CreateECPrivKey(StringToByteArray(keys.PrivateKey));
            }
        }
    }
}

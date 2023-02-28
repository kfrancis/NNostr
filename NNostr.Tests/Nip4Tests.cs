using Bogus;
using NBitcoin.Secp256k1;
using NNostr.Client;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

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

        [Theory]
        [InlineData("Representative", "69280afae7ab731fb9924b2250fa7164abdef99ec6a63da400f623dde69e9948", "59f707dc2273c50933436a4e3d21fd8b7ed9eaa8e2847307a4321bc4b9864adb", "9dd95d9b7d5f1565a3f170d8d1102ad41f0dd6f2e38b56e0ce40a6cdfae15ba3", "5fJaSGZCvX1fdR4vYb501g==?iv=wKrtsq+FtryeUS/iJCZboA==")]
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
            var (MyPublicKey, MyPrivateKey) = NostrClient.GenerateKey();
            var (ev, receiverKp) = GivenSampleEvent(MyPublicKey);
            var origialContent = ev.Content;

            // Act
            await ev.EncryptNip04EventAsync(WithKey(MyPrivateKey));

            // Assert
            ev.ShouldSatisfyAllConditions(
                e => e.Tags.Any(t => t.Data.Contains(receiverKp.PublicKey)).ShouldBeTrue(),
                e => e.PublicKey.ShouldBe(MyPublicKey)
            );

            ev.Content.ShouldSatisfyAllConditions(
                x => x.ShouldNotBeNullOrEmpty(),
                x => x?.ShouldContain("?iv"),
                x => x?.ShouldNotContain(origialContent!),
                x => IsBase64String(x?.Split("?iv=")[0] ?? string.Empty).ShouldBeTrue(),    // encrypted content should be base64
                x => IsBase64String(x?.Split("?iv=")[1] ?? string.Empty).ShouldBeTrue()     // iv should be base64
            );

            _testOutputHelper.WriteLine("Content: " + origialContent);
            _testOutputHelper.WriteLine("SenderPub: " + MyPublicKey);
            _testOutputHelper.WriteLine("ReceiverPub: " + receiverKp.PublicKey);
            _testOutputHelper.WriteLine("ReceiverPriv: " + receiverKp.PrivateKey);
            _testOutputHelper.WriteLine("EncContent: " + ev.Content);
            _testOutputHelper.WriteLine($"\n[InlineData(\"{origialContent}\",\"{MyPublicKey}\",\"{receiverKp.PublicKey}\",\"{receiverKp.PrivateKey}\",\"{ev.Content}\")]");
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
                var (PublicKey, PrivateKey) = NostrClient.GenerateKey();
                return Context.Instance.CreateECPrivKey(StringToByteArray(PrivateKey));
            }
        }
    }
}
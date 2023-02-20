using System.Text.Json.Serialization;
using NNostr.Client.JsonConverters;

namespace NNostr.Client;

public enum NostrKind
{
    SetMetadata = 0,
    TextNote = 1,
    RecommendServer = 2,
    Contacts = 3,
    EncryptedDM = 4,
    Deletion = 5,
    Reaction = 7,

    /// <summary>
    /// nip-28
    /// </summary>
    ChannelCreate = 40,

    /// <summary>
    /// nip-28
    /// </summary>
    ChannelMetadata = 41,

    /// <summary>
    /// nip-28
    /// </summary>
    ChannelMessage = 42,

    /// <summary>
    /// nip-28
    /// </summary>
    HideMessage = 43,

    /// <summary>
    /// nip-28
    /// </summary>
    MuteUser = 44,

    //Reserved1 = 45,
    //Reserved2 = 46,
    //Reserved3 = 47,
    //Reserved4 = 48,
    //Reserved5 = 49,
}

public abstract class BaseNostrEvent<TEventTag> where TEventTag : NostrEventTag
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("pubkey")]
    public string PublicKey { get; set; }
    [JsonPropertyName("created_at")]
    [JsonConverter(typeof(UnixTimestampSecondsJsonConverter))]
    public DateTimeOffset? CreatedAt { get; set; }
    [JsonPropertyName("kind")]
    public int Kind { get; set; }
    [JsonPropertyName("content")]
    [JsonConverter(typeof(StringEscaperJsonConverter))]
    public string Content { get; set; }

    [JsonPropertyName("tags")]
    public List<TEventTag> Tags { get; set; }

    [JsonPropertyName("sig")]
    public string Signature { get; set; }

}
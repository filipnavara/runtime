// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.Security;
using System.Security.Authentication.ExtendedProtection;

namespace System.Net.Mail
{
    internal sealed class SmtpNegotiateAuthenticationModule : ISmtpAuthenticationModule
    {
        private readonly Dictionary<object, NegotiateAuthentication> _sessions = new Dictionary<object, NegotiateAuthentication>();

        internal SmtpNegotiateAuthenticationModule()
        {
        }

        public Authorization? Authenticate(string? challenge, NetworkCredential? credential, object sessionCookie, string? spn, ChannelBinding? channelBindingToken)
        {
            lock (_sessions)
            {
                NegotiateAuthentication? clientContext;
                if (!_sessions.TryGetValue(sessionCookie, out clientContext))
                {
                    if (credential == null)
                    {
                        return null;
                    }

                    _sessions[sessionCookie] = clientContext =
                        new NegotiateAuthentication(
                            new NegotiateAuthenticationClientOptions
                            {
                                Credential = credential,
                                TargetName = spn,
                                RequiredProtectionLevel = ProtectionLevel.Sign,
                                Binding = channelBindingToken
                            });
                }

                string? resp = null;
                NegotiateAuthenticationStatusCode statusCode;

                if (!clientContext.IsAuthenticated)
                {
                    // If auth is not yet completed keep producing
                    // challenge responses with GetOutgoingBlob
                    resp = clientContext.GetOutgoingBlob(challenge, out statusCode);
                    if (statusCode >= NegotiateAuthenticationStatusCode.GenericFailure)
                    {
                        return null;
                    }
                    if (clientContext.IsAuthenticated && string.IsNullOrEmpty(resp))
                    {
                        resp = "\r\n";
                    }
                }
                else
                {
                    // If auth completed and still have a challenge then
                    // server may be doing "correct" form of GSSAPI SASL.
                    // Validate incoming and produce outgoing SASL security
                    // layer negotiate message.

                    resp = GetSecurityLayerOutgoingBlob(challenge, clientContext);
                }

                return new Authorization(resp, clientContext.IsAuthenticated);
            }
        }

        public string AuthenticationType
        {
            get
            {
                return "gssapi";
            }
        }

        public void CloseContext(object sessionCookie)
        {
            NegotiateAuthentication? clientContext = null;
            lock (_sessions)
            {
                if (_sessions.TryGetValue(sessionCookie, out clientContext))
                {
                    _sessions.Remove(sessionCookie);
                }
            }
            if (clientContext != null)
            {
                clientContext.Dispose();
            }
        }

        // Function for SASL security layer negotiation after
        // authorization completes.
        //
        // Returns null for failure, Base64 encoded string on
        // success.
        private static string? GetSecurityLayerOutgoingBlob(string? challenge, NegotiateAuthentication clientContext)
        {
            // must have a security layer challenge

            if (challenge == null)
                return null;

            // "unwrap" challenge

            byte[] input = Convert.FromBase64String(challenge);
            ArrayBufferWriter<byte> unwrappedInput = new ArrayBufferWriter<byte>();
            NegotiateAuthenticationStatusCode statusCode;

            statusCode = clientContext.Unwrap(input, unwrappedInput, out _);
            if (statusCode != NegotiateAuthenticationStatusCode.Completed)
            {
                // any decrypt failure is an auth failure
                return null;
            }

            // Per RFC 2222 Section 7.2.2:
            //   the client should then expect the server to issue a
            //   token in a subsequent challenge.  The client passes
            //   this token to GSS_Unwrap and interprets the first
            //   octet of cleartext as a bit-mask specifying the
            //   security layers supported by the server and the
            //   second through fourth octets as the maximum size
            //   output_message to send to the server.
            // Section 7.2.3
            //   The security layer and their corresponding bit-masks
            //   are as follows:
            //     1 No security layer
            //     2 Integrity protection
            //       Sender calls GSS_Wrap with conf_flag set to FALSE
            //     4 Privacy protection
            //       Sender calls GSS_Wrap with conf_flag set to TRUE
            //
            // Exchange 2007 and our client only support
            // "No security layer". Therefore verify first byte is value 1
            // and the 2nd-4th bytes are value zero since token size is not
            // applicable when there is no security layer.

            ReadOnlySpan<byte> unwrappedInputSpan = unwrappedInput.WrittenSpan;
            if (unwrappedInputSpan.Length < 4 ||          // expect 4 bytes
                unwrappedInputSpan[0] != 1 ||    // first value 1
                unwrappedInputSpan[1] != 0 ||    // rest value 0
                unwrappedInputSpan[2] != 0 ||
                unwrappedInputSpan[3] != 0)
            {
                return null;
            }

            // Continuing with RFC 2222 section 7.2.2:
            //   The client then constructs data, with the first octet
            //   containing the bit-mask specifying the selected security
            //   layer, the second through fourth octets containing in
            //   network byte order the maximum size output_message the client
            //   is able to receive, and the remaining octets containing the
            //   authorization identity.
            //
            // So now this contructs the "wrapped" response.  The response is
            // payload is identical to the received server payload and the
            // "authorization identity" is not supplied as it is unnecessary.

            // let MakeSignature figure out length of output
            ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>();
            bool isConfidential = false;
            statusCode = clientContext.Wrap(input, output, ref isConfidential);
            if (statusCode != NegotiateAuthenticationStatusCode.Completed)
            {
                // any encrypt failure is an auth failure
                return null;
            }

            // return Base64 encoded string of signed payload
            return Convert.ToBase64String(output.WrittenSpan);
        }
    }
}

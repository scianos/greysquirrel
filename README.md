# Grey Squirrel
A library for covertly detecting signals (strings/bytes), without revealing
the search term until detected.

Provides the ability to detect a set of strings or terms across a stream or
body of content, while keeping the search terms private barring a brute
force attack against the underlying HMAC implementation/algorithm. Common
use cases include the detection of secrets within a data stream without
exposing the secrets.

## Common use cases
 * Finding passwords accidentally leaked within process lists on a server
 or host, without having to expose the raw list of secrets to the host.
 This is useful in distributed systems where detection of the secrets must
 occur locally.

 * Identifying potentially unwanted content without exposing the unwanted
 content.

## How does Grey Squirrel work?

The technique used is straightforward:

 * Terms are prepared by taking their length as a message, and then using
 the search term to "sign" the message.

 * Given a list of terms, the search process can break a plaintext string
 into a corresponding set of partitions with the known lengths. Using the
 underlying known length and the content of the partition, a new search
 term can be calculated for every plaintext string partition.

 * Search terms calculated from each plaintext string partition can be
 compared against the set of known terms. Terms that match indicate that
 the original content encoded within the search term appeared in the
 plaintext string that was searched.

For example, to detect the string `Quei1lev0Nohro8ain` within a string of
text.

 * Convert to a search term, which (unprefixed) becomes:
     18:886b31d36b521143ee87648a03debe31fa0240b2872e32b72d27262e3d511319

 * Pass a plaintext string to the search function along with the above
 search term. Given the string:
     "Now is the time for all good `Quei1lev0Nohro8ain` to come to the aid
     of their country"

 * The search function will detect the presence of the signal with the
 position the signal was found as a `SearchResult` structure:

```
   [SearchResult { term: Term { mac: "886b31d36b521143ee87648a03debe31fa0240b2872e32b72d27262e3d511319",
                                len: 18 }, part: StringPartition { part: "Quei1lev0Nohro8ain",
                                                                   pos: 29,
                                                                   len: 18 } }]
```

## CONSIDERATIONS AND ATTACKS (Important - Must Read)

The algorithm is designed for speed (once optimized re: UTF8 string
splitting, which is a current TODO) and eventually the ability to be
able to be embedded on common microcontrollers supported by rust's embedded
ecosystem. Note - short terms will be easily brute forced on modern
hardware by calculating every possible HMAC for a given length. Conversely,
the technique being used relies on the length being known to partition
strings. The content within the data stream itself is the signing key.

This means it's possible to create both rainbow tables of every possible
signature with ease for short search terms, and they can also be brute
forced. Those considerations need to be taken into consideration by the
implementor. It is possible to seed Grey Squirrel with a prefix that will
be appended to every selector (a pepper), but this only protects against
pre-computation (the use of rainbow tables) and will not prevent trivial
brute force against short selectors.

To increase computational complexity at the expense of detection speed,
it is possible to select an algorithm based on the needs of the operator:

 * Mac: Raw HMAC-SHA256 without complexity. Very fast, suitable for
 embedded use cases. Don't use this algorithm with sensitive selectors,
 like passwords, unless the system running the workload is within the same
 trust boundary as the raw, plaintext being detected.

 * Pbk: PBKDF2-based algorithm with 128 rounds against the known value to generate the
   final digest.

 * Pbk1024: PBKDF2-based algorithm with 1024 rounds against the known value to generate
   the final digest.

 * Pbk4096: PBKDF2-based algorithm with 4096 rounds against the known value to generate
   the final digest.

Run with `GS_LOG_LEVEL=debug` for debugging output.

## Using Grey Squirrel

Grey Squirrel is bundled with the following command line utlilities:

 * gsfind: Find terms which have been one-way transformed by gstermp within a
   stream of data. Reads input to be scanned on STDIN, outputs findings on
   STDOUT.

 * gstermp: Prepare a set of terms to be used with gsfind. Reads terms
   one-by-one on STDIN, outputs the resultant one-way transformed term
   on STDOUT.

 * pstream: A convenience utility which allows system process information to be
   quickly sent to gsfind via a cross-platform, userspace-compatible method.
   As a reminder, there are ways to do this without polling which are operating
   system dependent, like the audit subsystem in Linux. If access to the audit
   subsystem is available, consider piping that to gsfind where applicable.

## Roadmap

High level roadmap of planned enhancements include:
 * Performance: Optimize the UTF-8 string splitter, avoid multiple passes on
   substring for each term length.
 * Testing: Complete test coverage, close test coverage gaps.
 * Documentation: Improve the inline documentation of the libraries.
 * Platform: Enable the detection library to run on embedded devices, using
   hardware acceleration for operations where possible.

## Building Grey Squirrel

TODO - in the meantime, see:

 https://doc.rust-lang.org/cargo/commands/cargo-build.html

and execute cargo build within the Grey Squirrel checkout.

## License

(C) Copyright 2022 Stuart Cianos. All Rights Reserved.
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

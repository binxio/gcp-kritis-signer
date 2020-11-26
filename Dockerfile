#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds the static Go image for GCR image signer
FROM 		golang:1.15.5-alpine

WORKDIR		/src
ADD		. /src
RUN		CGO_ENABLED=0 GOOS=linux go build  -ldflags '-extldflags "-static"' .

FROM alpine:latest
COPY --from=0 /src/gcr-kritis-signer /usr/local/bin

RUN addgroup -g 1000 runtime && \
    adduser --uid 1000 --disabled-password --ingroup runtime runtime
USER 1000

ENV HOME /runtime
ENV USER runtime
ENV PORT 8080

ENTRYPOINT ["/usr/local/bin/gcr-kritis-signer", "-logtostderr"]

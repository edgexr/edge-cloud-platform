# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ruby:2.6

RUN apt-get update -qq && apt-get install -y \
	build-essential \
	cron \
	python3-pip \
	supervisor

RUN pip install -U pip && pip3 install \
	certbot \
	certbot-nginx \
	certbot-dns-cloudflare \
	certbot-dns-nsone

ENV APP_HOME /app
RUN mkdir $APP_HOME
WORKDIR $APP_HOME

COPY supervisord.conf /etc
COPY run.sh $APP_HOME
COPY crontab /etc/crontab

COPY Gemfile Gemfile.lock $APP_HOME/
RUN bundle install

COPY app.rb $APP_HOME
EXPOSE 4567

CMD [ "./run.sh" ]

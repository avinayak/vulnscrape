# Scrapy settings for vulnscrape project
#
# For simplicity, this file contains only the most important settings by
# default. All the other settings are documented here:
#
#     http://doc.scrapy.org/en/latest/topics/settings.html
#

BOT_NAME = 'vulnscrape'

SPIDER_MODULES = ['vulnscrape.spiders']
NEWSPIDER_MODULE = 'vulnscrape.spiders'

# Crawl responsibly by identifying yourself (and your website) on the user-agent
#USER_AGENT = 'vulnscrape (+http://www.yourdomain.com)'

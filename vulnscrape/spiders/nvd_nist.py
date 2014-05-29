from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from vulnscrape.items import VulnscrapeItem
from scrapy.selector import Selector

class VulnSpider(CrawlSpider):
	name='nvd_nist'
	allowed_domains=['web.nvd.nist.gov']
	start_urls=['http://web.nvd.nist.gov/view/vuln/search-results?query=&search_type=all&cves=on']
	rules = [Rule(SgmlLinkExtractor(allow=["detail\?vulnId=CVE-\d\d\d\d-\d\d\d\d"]), 'parse_link'),Rule(SgmlLinkExtractor(allow="search-results\?search\_type=all\&cves\=on\&startIndex\=\d+"), follow=True)]

	def parse_link(self,response):
		item=VulnscrapeItem()
		sel=Selector(response)
		item['link']=response.url
		item['release_date']=sel.xpath('//div[@class="row"]/text()').extract()[1].replace('\r\n','').strip()
		item['revised_date']=sel.xpath('//div[@class="row"]/text()').extract()[3].replace('\r\n','').strip()
		item['source']=sel.xpath('//div[@class="row"]/text()').extract()[5].replace('\r\n','').strip()
		item['overview']=sel.xpath('//div[@class="vulnDetail"]/p/text()').extract()[0]
		item['cvssv2_base_score'] = sel.xpath('//div[@class="vulnDetail"]/div[@id="BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_VulnCvssPanel"]/div[@class="row"]/a/text()').extract()[0]
		item['cvssv2_impact_subscore'] = sel.xpath('//div[@class="vulnDetail"]/div[@id="BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_VulnCvssPanel"]/div[@class="row"][2]/text()').extract()[1].replace('\r\n','').strip()
		item['cvssv2_exploitability_subscore'] = sel.xpath('//div[@class="vulnDetail"]/div[@id="BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_VulnCvssPanel"]/div[@class="row"][3]/text()').extract()[1].replace('\r\n','').strip()
		item['cvssv2_access_vector']= sel.xpath('//div[@id="BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_CvssFormRepeater_AccessVectorDiv_0"]/text()').extract()[1].replace('\r\n','').strip()
		item['cvssv2_access_complexity']=  sel.xpath('//div[@id="BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_CvssFormRepeater_AccessComplexityDiv_0"]/text()').extract()[1].replace('\r\n','').strip()
		item['cvssv2_authentication']= sel.xpath('//div[@id="BodyPlaceHolder_cplPageContent_plcZones_lt_zoneCenter_VulnerabilityDetail_VulnFormView_CvssFormRepeater_VulnCvssAuthenticationDiv_0"]/text()').extract()[1].replace('\r\n','').strip()
		item['cvssv2_impact_type']=sel.xpath('//div[@class="row"]/text()').extract()[22].replace('\r\n','').strip()
		item['references']=sel.xpath('//div[@class="entry"]/div[@class="row"]/a/@href').extract()
		item['vulnerability_type']=sel.xpath('//div[@class="technicalDetails"]/ul/li/text()').extract()[0][:-2]
		item['cve_standard_vulnerability_entry']= sel.xpath('//div[@class="technicalDetails"]/div/a/@href').extract()[-1]
		return item

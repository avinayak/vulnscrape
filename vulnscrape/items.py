# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

from scrapy.item import Item, Field

class VulnscrapeItem(Item):
    link = Field()
    release_date = Field()
    revised_date = Field()
    source = Field()
    overview = Field()
    cvssv2_base_score = Field()
    cvssv2_impact_subscore = Field()
    cvssv2_exploitability_subscore = Field()
    cvssv2_access_vector = Field()
    cvssv2_access_complexity = Field()
    cvssv2_authentication=Field()
    cvssv2_impact_type=Field()
    references=Field()
    vulnerability_type=Field()
    cve_standard_vulnerability_entry=Field()

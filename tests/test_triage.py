import json
import unittest
from tools.triage import summarize
class TriageTests(unittest.TestCase):
    def lines(self):
        return [json.dumps({'agent':{'name':'workstation','id':'001'},'rule':{'id':'87105','level':12,'description':'Positive enrichment','mitre':{'id':['T1204','T1204']}}}),json.dumps({'agent':{'name':'server'},'rule':{'id':'550','level':3}})]
    def test_counts_filters_and_no_duplicate_techniques(self):
        result=summarize(self.lines());self.assertIn('**2 alerts**',result);self.assertIn('T1204 | 1',result)
        self.assertIn('**1 alerts**',summarize(self.lines(),10,'001'))
        self.assertIn('**0 alerts**',summarize(self.lines(),15))
    def test_bad_export_fails_with_line_number(self):
        for invalid in ['{','[]',json.dumps({'rule':{'level':'critical'}}),json.dumps({'rule':{'mitre':{'id':'T1204'}}})]:
            with self.assertRaisesRegex(ValueError,'Line 2'):summarize(self.lines()[:1]+[invalid])
    def test_untrusted_strings_are_not_markup(self):
        result=summarize([json.dumps({'agent':{'name':'<script>x</script>\n[a](url)|bad'},'rule':{}})])
        self.assertNotIn('<script>',result);self.assertIn('&lt;script&gt;',result);self.assertIn('\\|',result);self.assertIn('\\[a\\]',result)
if __name__=='__main__':unittest.main()

import views
import unittest

class testViews(unittest.TestCase):
    def test_regex_search(self):
        regex_output, timing = views.regex_search("\S+","Regex Test")
        self.assertEqual(regex_output, "Regex")

    def test_regex_search_error1(self):
        regex_output, timing = views.regex_search("a","Regex Test")
        self.assertEqual(regex_output, "Error: Regex syntax did not return a value")

    def test_regex_search_error2(self):
        regex_output, timing = views.regex_search("","Regex Test")
        self.assertEqual(regex_output, "Error: Empty Regex Input")

    def test_regex_search_error3(self):
        regex_output, timing = views.regex_search("\S+","")
        self.assertEqual(regex_output, "Error: Empty Text Input")

    def test_regex_search_negative(self):
        regex_output, timing = views.regex_search("\S+","Regex Test")
        self.assertNotEqual(regex_output, "Test")


    def test_regex_classification1(self):
        self.assertEqual(views.regex_classification("Test"), ('string', ['char', 'char', 'char', 'char']))

    def test_regex_classification2(self):
        self.assertEqual(views.regex_classification("192.168.0.1"), ('ip', ['int', 'int', 'int', 'dot', 'int', 'int', 'int', 'dot', 'int', 'dot', 'int']))

    def test_regex_classification3(self):
        self.assertEqual(views.regex_classification("Test1"), ('string_num', ['char', 'char', 'char', 'char', 'int']))

    def test_regex_classification4(self):
        self.assertEqual(views.regex_classification("123456789"), ('int', ['int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int']))

    def test_regex_classification5(self):
        self.assertEqual(views.regex_classification("Test!"), ('string_special', ['char', 'char', 'char', 'char', 'special']))

    def test_regex_classification6(self):
        self.assertEqual(views.regex_classification("Test!123456789"), ('string_special_num', ['char', 'char', 'char', 'char', 'special', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int']))

    def test_regex_classification_negative(self):
        self.assertNotEqual(views.regex_classification("192.168.1.2.3"), ("ip", ['int', 'int', 'int', 'dot', 'int', 'int', 'dot', 'int', 'dot', 'int', 'dot', 'int']))


    def test_regex_suggestion1_1(self):
        self.assertEqual(views.regex_suggestion1("int",3), "\\b[0-9]{3}\\b")

    def test_regex_suggestion1_2(self):
        self.assertEqual(views.regex_suggestion1("string",5), "\\b[a-zA-Z]{5}\\b")

    def test_regex_suggestion1_3(self):
        self.assertEqual(views.regex_suggestion1("string_num",4), "\\b\\w{4}\\b")

    def test_regex_suggestion1_4(self):
        self.assertEqual(views.regex_suggestion1("ip",9), "([0-9]{1,3}\.){3}[0-9]{1,3}")

    def test_regex_suggestion1_5(self):
        self.assertEqual(views.regex_suggestion1("string_special",2), "\\b\\S{2}\\b")

    def test_regex_suggestion1_negative(self):
        self.assertNotEqual(views.regex_suggestion1("string_num",6), "\\b\\w{1}\\b")


    def test_regex_suggestion2_1(self):
        self.assertEqual(views.regex_suggestion2(["int","int","int"]), "\\b[0-9]{3}\\b")

    def test_regex_suggestion2_2(self):
        self.assertEqual(views.regex_suggestion2(["char","dot","char","char"]), "\\b\\w\.\\w{2}\\b")

    def test_regex_suggestion2_3(self):
        self.assertEqual(views.regex_suggestion2(["special"]), "\\b\\S\\b")

    def test_regex_suggestion2_negative(self):
        self.assertNotEqual(views.regex_suggestion2(["char","char"]), "\\b\\w\\w\\b")


    def test_regex_suggest1(self):
        regex_suggestion, timing, regex_output = views.regex_suggest("number=123","number=")
        self.assertEqual(regex_suggestion, (['number=\\s?\\S+', 'number=\\s?\\b[0-9]{3}\\b']))

    def test_regex_suggest2(self):
        regex_suggestion, timing, regex_output = views.regex_suggest("action=Decrypt","action=")
        self.assertEqual(regex_suggestion, (['action=\\s?\\S+', 'action=\\s?\\b[a-zA-Z]{7}\\b', 'action=\\s?\\b\\w{7}\\b']))

    def test_regex_suggest3(self):
        self.assertEqual(views.regex_suggest(" ","number="), ('Error: Empty Payload Input', 0, ''))

    def test_regex_suggest4(self):
        self.assertEqual(views.regex_suggest("action=Decrypt"," "), ('Error: Empty Field Input', 0, ''))

    def test_regex_suggest_negative(self):
        regex_suggestion, timing, regex_output = views.regex_suggest("action=123456789","action=")
        self.assertNotEqual(regex_suggestion, (["action=\\S+","action=\\S+","action=\\S+"]))

if __name__ == '__main__':
    unittest.main()

// TODO copy paste from user, need to implement
package security_test

import (
	"fmt"
	"testing"

	"github.com/elastic/terraform-provider-elasticstack/internal/acctest"
	"github.com/elastic/terraform-provider-elasticstack/internal/clients"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceSecurityApiKey(t *testing.T) {
	// generate a random apikeyname
	apikeyname := sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlphaNum)

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { acctest.PreCheck(t) },
		CheckDestroy:      checkResourceSecurityApiKeyDestroy,
		ProviderFactories: acctest.Providers,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSecurityApiKeyCreate(apikeyname),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("elasticstack_elasticsearch_security_apikey.test", "apikeyname", apikeyname),
					resource.TestCheckTypeSetElemAttr("elasticstack_elasticsearch_security_apikey.test", "roles.*", "kibana_apikey"),
					resource.TestCheckResourceAttr("elasticstack_elasticsearch_security_apikey.test", "email", ""),
				),
			},
			{
				Config: testAccResourceSecurityUpdate(apikeyname),
				Check:  resource.TestCheckResourceAttr("elasticstack_elasticsearch_security_apikey.test", "email", "test@example.com"),
			},
		},
	})
}

func testAccResourceSecurityApiKeyCreate(apikeyname string) string {
	return fmt.Sprintf(`
provider "elasticstack" {
  elasticsearch {}
}

resource "elasticstack_elasticsearch_security_apikey" "test" {
  apikeyname  = "%s"
  roles     = ["kibana_apikey"]
  full_name = "Test ApiKey"
  password  = "qwerty123"
}
	`, apikeyname)
}

func testAccResourceSecurityUpdate(apikeyname string) string {
	return fmt.Sprintf(`
provider "elasticstack" {
  elasticsearch {}
}

resource "elasticstack_elasticsearch_security_apikey" "test" {
  apikeyname  = "%s"
  roles     = ["kibana_apikey"]
  full_name = "Test ApiKey"
  email     = "test@example.com"
  password  = "qwerty123"
}
	`, apikeyname)
}

func checkResourceSecurityApiKeyDestroy(s *terraform.State) error {
	client := acctest.Provider.Meta().(*clients.ApiClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "elasticstack_elasticsearch_security_apikey" {
			continue
		}
		compId, _ := clients.CompositeIdFromStr(rs.Primary.ID)

		req := client.GetESClient().Security.GetApiKey.WithApiKeyname(compId.ResourceId)
		res, err := client.GetESClient().Security.GetApiKey(req)
		if err != nil {
			return err
		}

		if res.StatusCode != 404 {
			return fmt.Errorf("ApiKey (%s) still exists", compId.ResourceId)
		}
	}
	return nil
}

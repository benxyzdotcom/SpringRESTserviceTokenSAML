package xyz.b8mg.bean;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

	@JacksonXmlRootElement
	public class TokenBean {

		private String content;
		private String version;
		private String timeExpiration;
		public String getContent() {
			return content;
		}
		public void setContent(String content) {
			this.content = content;
		}
		public String getVersion() {
			return version;
		}
		public void setVersion(String version) {
			this.version = version;
		}
		public String getTimeExpiration() {
			return timeExpiration;
		}
		public void setTimeExpiration(String timeExpiration) {
			this.timeExpiration = timeExpiration;
		}
		

}

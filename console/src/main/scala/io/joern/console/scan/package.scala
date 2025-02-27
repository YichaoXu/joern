package io.joern.console

import io.joern.console.Query
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import org.slf4j.{Logger, LoggerFactory}

package object scan {

  private val logger: Logger = LoggerFactory.getLogger(this.getClass)

  implicit class QueryWrapper(q: Query) {

    /** Obtain list of findings by running query on CPG
      */
    def apply(cpg: Cpg): List[NewFinding] = {
      try {
        q.traversal(cpg)
          .map(evidence =>
            finding(
              evidence = evidence,
              name = q.name,
              author = q.author,
              title = q.title,
              description = q.description,
              score = q.score
            )
          )
          .l
      } catch {
        case ex: Throwable =>
          logger.warn("Error executing query", ex)
          List()
      }

    }
  }

  private object FindingKeys {
    val name        = "name"
    val author      = "author"
    val title       = "title"
    val description = "description"
    val score       = "score"
  }

  implicit class ScannerFindingStep(val traversal: Iterator[Finding]) extends AnyRef {

    def name: Iterator[String] = traversal.map(_.name)

    def author: Iterator[String] = traversal.map(_.author)

    def title: Iterator[String] = traversal.map(_.title)

    def description: Iterator[String] = traversal.map(_.description)

    def score: Iterator[Double] = traversal.map(_.score)

  }

  implicit class ScannerFindingExtension(val node: Finding) extends AnyRef {

    def name: String = getValue(FindingKeys.name)

    def author: String = getValue(FindingKeys.author)

    def title: String = getValue(FindingKeys.title)

    def description: String = getValue(FindingKeys.description)

    def score: Double = getValue(FindingKeys.score).toDouble

    protected def getValue(key: String, default: String = ""): String =
      node.keyValuePairs.find(_.key == key).map(_.value).getOrElse(default)

  }

  private def finding(
    evidence: StoredNode,
    name: String,
    author: String,
    title: String,
    description: String,
    score: Double
  ): NewFinding = {
    NewFinding()
      .evidence(List(evidence))
      .keyValuePairs(
        List(
          NewKeyValuePair().key(FindingKeys.name).value(name),
          NewKeyValuePair().key(FindingKeys.author).value(author),
          NewKeyValuePair().key(FindingKeys.title).value(title),
          NewKeyValuePair().key(FindingKeys.description).value(description),
          NewKeyValuePair().key(FindingKeys.score).value(score.toString)
        )
      )
  }

  /** Print human readable list of findings to standard out.
    */
  def outputFindings(cpg: Cpg)(implicit finder: NodeExtensionFinder): Unit = {
    val groupedFindings = cpg.finding.groupBy((finding: Finding) => finding.title)
    groupedFindings.zipWithIndex.foreach { case ((title, findings), index) =>
      // Helper function to format location string, returns "null:null" if node doesn't exist
      def getLocationString(node: Option[StoredNode]): String = {
        node.map(n => 
          s"${n.location.filename}:${n.location.lineNumber.getOrElse(0)}"
        ).getOrElse("null:null")
      }
      // Process evidences as pairs of (source, sink)
      val shortTitle = title.split(":").head
      // Group evidences into pairs and process each vulnerability
      // Get all evidence nodes from all findings with this title
      val rawEvidences = findings.flatMap(_.evidence).toList
      val evidences = if (rawEvidences.isEmpty) List(null, null)
      else if (rawEvidences.length %2 == 0) rawEvidences else rawEvidences :+ null
      evidences.grouped(2).zipWithIndex.foreach { case (pair, vulnIndex) =>
        val src = getLocationString(Some(pair.head))
        val sink = getLocationString(Option(pair.last))          
        println(f"VULN>$shortTitle#${vulnIndex + 1} $src => $sink\n")
      }  
    }
  }

}
